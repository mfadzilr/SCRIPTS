# !/usr/bin/env ruby
# encoding:UTF-8
# pj@2021

require 'optparse'
require 'openssl'
require 'securerandom'

ALLOWED_ALGO = /#{Regexp.union(["aes", "xor"]).source}/i
options = {}

option_parser = OptionParser.new do |opt|
    opt.on('-f', '--file FILENAME', 'filename') { |o| options[:file] = o }
    opt.on('-s', '--string STRING', 'plaintext string') { |o| options[:string] = o }
    opt.on('-e', '--encrypt ALGO', ALLOWED_ALGO, 'algo type ( AES | XOR )') { |o| options[:algo] = o.downcase }
    opt.on('-k', '--key KEY', 'encryption key') { |o| options[:key] = o }
end

begin
    option_parser.parse!
    if !options.any? or (options[:file] and options[:string])
        puts option_parser
        exit 0
    end
rescue OptionParser::ParseError => e
    puts "[!] Error: #{e}"
    exit 0
end

# print output
def print_hex_data(data)
    if !data.is_a?(Array)
        data = data.chars
    end

    puts "{ "
    data.each_with_index.each_slice(8) { |line|
        output = Array.new
        output << "    "
        line.each { |char|
            output << "0x%02X" % [char[0].ord]
            unless char[1] == data.size - 1
                output << ", "
            end
        }
        puts output.join
    }
    puts " };"
end

# need to digest plaintext key
def digest_key(plaintext_pass)
    sha256 = OpenSSL::Digest::SHA256.new
    key_digest = sha256.digest(plaintext_pass)
    puts "[ ENCRYPTION KEY ]"
    print_hex_data(plaintext_pass)
    return key_digest
end

# XOR encryption
def encrypt_xor(data, plaintext_pass)
    output = Array.new
    (data.chars).each_index do |i|
        output.push((data[i].ord ^ plaintext_pass[i % plaintext_pass.length].ord).chr)
    end
    return output
end

# AES encryption
def encrypt_aes(data, plaintext_pass)
    aes = OpenSSL::Cipher::AES256.new(:CBC)
    aes.encrypt
    aes.key = digest_key(plaintext_pass)
    aes.iv = "\x00" * 16
    return aes.update(data) + aes.final
end

if options[:file]
    begin
        file = File.open(options[:file], "rb")
        data = file.read
        file.close
    rescue Exception => e
        puts "[!] Error: #{e}"
        exit 0
    end
elsif options[:string]
    data = options[:string]
end

case options[:algo]
    when "xor"
        if options[:key]
            pass = options[:key]
        else
            pass = SecureRandom.alphanumeric(16)
        end
        puts "[ ENCRYPTION KEY ]"
        puts pass
        puts
        encrypted_data = encrypt_xor(data, pass)
        puts "[ ENCRYPTED PAYLOAD ]"
        print_hex_data(encrypted_data)
    when "aes"
        if options[:key]
            pass = options[:key]
        else
            pass = SecureRandom.alphanumeric(16)
        end
        encrypted_data = encrypt_aes(data, pass)
        puts "[ ENCRYPTED DATA ]"
        print_hex_data(encrypted_data)
    else
        puts "[ PLAIN DATA ]"
        print_hex_data(data)
end

