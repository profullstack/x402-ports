# frozen_string_literal: true

# +coinpay+ from RubyGems: a launcher for the CoinPay CLI, @profullstack/coinpay on npm.
#
# Order: $COINPAY_BIN; a coinpay on PATH that is not this launcher; then npx,
# bunx, pnpm dlx or deno run. $COINPAY_VERSION pins the npm version.
module Coinpay
  VERSION = "0.1.0"
  PACKAGE = "@profullstack/coinpay"

  module_function

  def spec
    v = ENV["COINPAY_VERSION"].to_s
    v.empty? ? PACKAGE : "#{PACKAGE}@#{v}"
  end

  def which(name)
    exts = Gem.win_platform? ? [".exe", ".cmd", ".bat", ""] : [""]
    ENV.fetch("PATH", "").split(File::PATH_SEPARATOR).each do |dir|
      exts.each do |ext|
        p = File.join(dir, "#{name}#{ext}")
        return p if File.file?(p) && File.executable?(p)
      end
    end
    nil
  end

  def real_cli(me = $PROGRAM_NAME)
    found = which("coinpay")
    return nil if found.nil?

    same = begin
      File.realpath(found) == File.realpath(me)
    rescue StandardError
      false
    end
    same ? nil : found
  end

  def command(args, me: $PROGRAM_NAME)
    exe = ENV["COINPAY_BIN"].to_s
    return [exe, *args] unless exe.empty?

    real = real_cli(me)
    return [real, *args] if real
    return ["npx", "--yes", spec, *args] if which("npx")
    return ["bunx", spec, *args] if which("bunx")
    return ["pnpm", "dlx", spec, *args] if which("pnpm")
    return ["deno", "run", "-A", "npm:#{spec}", *args] if which("deno")

    nil
  end

  def main(args = ARGV)
    cmd = command(args)
    if cmd.nil?
      warn "coinpay: the CoinPay CLI runs on Node.js 20+ (or Bun or Deno), and none was found.\n" \
           "  Install Node from https://nodejs.org, then either run this command again\n" \
           "  or install the CLI directly: npm install -g @profullstack/coinpay"
      return 127
    end
    system(*cmd)
    $CHILD_STATUS ? $CHILD_STATUS.exitstatus || 1 : 126
  rescue Interrupt
    130
  end
end
