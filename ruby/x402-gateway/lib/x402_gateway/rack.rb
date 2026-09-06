# frozen_string_literal: true

require "cgi"

module X402Gateway
  # Rack middleware: Rails, Sinatra, Hanami, Roda, anything on Rack 2 or 3.
  #
  #   use X402Gateway::Rack, gateway                       # config.ru / Sinatra
  #   config.middleware.use X402Gateway::Rack, gateway     # Rails
  class Rack
    def initialize(app, gateway = nil, **options)
      @app = app
      @gateway = gateway || Gateway.new(**options)
    end

    def self.request_from_env(env)
      headers = {}
      env.each do |k, v|
        headers[k[5..].tr("_", "-").downcase] = v if k.start_with?("HTTP_")
      end
      headers["content-type"] ||= env["CONTENT_TYPE"] if env["CONTENT_TYPE"]
      host = headers["host"] || env["SERVER_NAME"] || "localhost"
      scheme = env["rack.url_scheme"] || "http"
      path = "#{env['SCRIPT_NAME']}#{env['PATH_INFO']}"
      path = "/" if path.empty?
      qs = env["QUERY_STRING"].to_s
      url = "#{scheme}://#{host}#{path}#{qs.empty? ? '' : "?#{qs}"}"
      Request.new(url: url, headers: headers, method: env["REQUEST_METHOD"] || "GET")
    end

    def call(env)
      answer = @gateway.handle(self.class.request_from_env(env))
      return @app.call(env) if answer.nil?

      body = answer.body.b
      [answer.status, answer.headers.merge("content-length" => body.bytesize.to_s), [body]]
    end
  end
end
