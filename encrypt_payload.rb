# !/usr/bin/env ruby
# encoding:UTF-8
# pj@2021

require 'optparse'
require 'openssl'
require 'securerandom'

options = {}

option_parser = OptionParser.new do |opt|
    opt.on('-f', '--file FILENAME', 'filename') { |o| options[:file] = o }
    opt.on('-s', '--string STRING', 'string') { |o| options[:string] = o }
    opt.on('-c', '--crypto AES|XOR', 'crypto type') { |o| options[:crypto] = o }
    opt.on('-k', '--key KEY', 'encryption key (xor)') { |o| options[:key] = o }
end
option_parser.parse!

def print_encrypted_data(data)
    if !data.is_a?(Array)
        data = data.chars
    end

    puts "{ "
    data.each_with_index.each_slice(8) { |line|
        output = Array.new
        line.each { |x|
            output << "\t"
            output << "0x%02X" % [x[0].ord]
            unless x[1] == data.size - 1
                output << ", "
            end
        }
        puts output.join
    }
    puts " };"
end

def digest_key(plaintext_pass)
    sha256 = OpenSSL::Digest::SHA256.new
    key_digest = sha256.digest(plaintext_pass)
    puts "[ ENCRYPTION KEY ]"
    print_encrypted_data(plaintext_pass).to_s
    return key_digest
end

def encrypt_xor(data, plaintext_pass)
    output = Array.new
    (data.chars).each_index do |i|
        output.push((data[i].ord ^ plaintext_pass[i % plaintext_pass.length].ord).chr)
    end
    return output
end

def encrypt_aes(data, plaintext_pass)
    cipher = OpenSSL::Cipher::AES256.new(:CBC)
    cipher.encrypt
    cipher.iv = "\x00" * 16
    cipher.key = digest_key(plaintext_pass)
    return cipher.update(data) + cipher.final
end

if options[:crypto].nil?
    puts "[!] -c crypto is required"
    exit 1
end

if options[:file] && options[:string]
    puts "[i] -f or -s only, can't have both."
    exit 1
end

if options[:file]
    data = File.open(options[:file], "rb") { |f| f.read }
elsif options[:string]
    data = options[:string]
end

case options[:crypto].downcase
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
        puts "[ ENCRYPTED DATA ]"
        print_encrypted_data(encrypted_data)
    when "aes"
        encrypted_data = encrypt_aes(data, Random.urandom(16))
        puts "[ ENCRYPTED DATA ]"
        print_encrypted_data(encrypted_data.chars)
    else
        puts "[!] no such encryption"
end

