#! /opt/local/bin/ruby

require 'active_record'
require 'fileutils'
require 'resolv'
require 'socket'
require 'ipaddr'
require 'set'
require 'optparse'

#----------------------------------------------------------------------------------

options = {
  service_name: "ovpn-qa",
  vpn_network: "10.5.0.0",
  vpn_mask: "255.255.255.0",
  vpn_port: "1194",
  vpn_protocol: "udp"
}

parser = OptionParser.new do |opts|
  opts.banner = "Usage: script.rb [options]"

  opts.on("-d", "--database Database", "Example: jmineops_prod") do |v|
    options[:database] = v
  end

  opts.on("","--service_name Service Name", "default: opvpn-qa") do |v|
    options[:service_name] = v
  end

  opts.on("", "--vpn_network Vpn Network", "default: 10.5.0.0") do |v|
    options[:vpn_network] = v
  end

  opts.on("", "--vpn_mask Vpn Mask", "default: 255.255.255.0") do |v|
    options[:vpn_mask] = v
  end

  opts.on("", "--vpn_port Vpn Port", "default: 1194") do |v|
    options[:vpn_port] = v
  end

  opts.on("", "--vpn_protocol Vpn Protocol", "default: udp") do |v|
    options[:vpn_protocol] = v
  end

end.parse!

begin
  parser.parse!

  if options[:database].nil?
    puts "Error: database"
    exit 1
  end
rescue OptionParser::InvalidOption => e
  exit 1
end

#----------------------------------------------------------------------------------

# Gera IPs únicos dentro de uma rede
class IPGenerator
  def initialize(rede_ip, mascara)
    @rede = IPAddr.new("#{rede_ip}/#{mascara}")
    @ips_possiveis = @rede.to_range.to_a[1..-2] # remove o IP de rede e broadcast
    @ips_usados = Set.new
    @ips_usados.add(rede_ip)
  end

  def new_ip
    raise "error ip limits" if @ips_usados.size >= @ips_possiveis.size

    loop do
      ip = @ips_possiveis.sample
      unless @ips_usados.include?(ip)
        @ips_usados.add(ip)
        return ip.to_s
      end
    end
  end
end

def devices_config(network,network_mask)
  r = []
  begin
    sql = "SELECT name, address, netmask FROM devices WHERE address IS NOT NULL AND netmask IS NOT NULL;"
    result = ActiveRecord::Base.connection.execute (sql)

    list_devices = []
    result.each do |row|
      r << {:name => row["name"] , :ip=> row["address"] , :mask=> row["netmask"]}
    end
  rescue => e
    r = []
    $stderr.puts "#{e}"
  end

  generator = IPGenerator.new(network, network_mask)
  r.each do |d|
    begin
      address = generator.new_ip
      if address
        sql = "UPDATE devices SET address = '#{address}', netmask = '#{network_mask}' WHERE name = '#{d[:name]}';"
        ActiveRecord::Base.connection.execute (sql)
      end
    rescue => e
      $stderr.puts "#{e}"
    end
  end

  r = []
  begin
    sql = "SELECT name, address, netmask FROM devices WHERE address IS NOT NULL AND netmask IS NOT NULL;"
    result = ActiveRecord::Base.connection.execute (sql)

    list_devices = []
    result.each do |row|
      r << {:name => row["name"] , :ip=> row["address"] , :mask=> row["netmask"]}
    end
  rescue => e
    r = []
    $stderr.puts "#{e}"
  end
  return r
end

#----------------------------------------------------------------------------------

db = options[:database]
host = "localhost"
user = "developer"
pwd = "jigsaw"
adapter = "postgresql"

ActiveRecord::Base.establish_connection(
  adapter:  adapter,
  host:     host,
  database: db,
  username: user,
  password: pwd
)

openvpnCaPath = "/home/jigsaw/openvpn-ca"
ovpnFilesPath = "#{openvpnCaPath}/ovpn_files"
password = "jigsaw"
host = Socket.gethostname
serviceName = options[:service_name]
serverPath = "/etc/openvpn/server"
clientPath = "/etc/openvpn/client"
ccdPath = "/etc/openvpn/ccd"
vpnNetwork = options[:vpn_network]
vpnMask = options[:vpn_mask]
vpnPort = options[:vpn_port]
vpnProtocol = options[:vpn_protocol]

system("rm -rf #{openvpnCaPath} ")
system("mkdir -p #{openvpnCaPath}")
system("mkdir -p #{ovpnFilesPath}")

system("sudo rm -rf #{serverPath}/*")
system("sudo mkdir -p #{ccdPath}")

system("sudo systemctl stop openvpn-server@#{serviceName}")
system("sudo systemctl disable openvpn-server@#{serviceName}")

Dir.chdir(openvpnCaPath) do
  system("cp -r /usr/share/easy-rsa/* .")
  system("./easyrsa init-pki")

  system("touch pki/.rnd")
  system("chmod 600 pki/.rnd")
  system("openssl rand -out pki/.rnd 256")
  system("openssl genrsa -aes256 -passout pass:#{password} -out pki/private/ca.key 2048 -rand pki/.rnd")

  system("./easyrsa --batch build-ca nopass")
  system("./easyrsa gen-dh")
  system("./easyrsa --batch build-server-full #{serviceName} nopass")
  system("./easyrsa gen-crl")

  system("sudo cp pki/ca.crt #{serverPath}")
  system("sudo cp pki/issued/#{serviceName}.crt #{serverPath}")
  system("sudo cp pki/private/#{serviceName}.key #{serverPath}")
  system("sudo cp pki/dh.pem #{serverPath}")

  system("sudo touch #{serverPath}/#{serviceName}.conf")

  lines = [
    "port #{vpnPort}",
    "proto #{vpnProtocol}",
    "dev tun",
    "server #{vpnNetwork} #{vpnMask}",
    "ca #{serverPath}/ca.crt",
    "cert #{serverPath}/#{serviceName}.crt",
    "key #{serverPath}/#{serviceName}.key",
    "dh #{serverPath}/dh.pem",
    "keepalive 10 120",
    "comp-lzo",
    "client-to-client",
    "client-config-dir #{ccdPath}",
    "persist-key",
    "persist-tun",
    "status /var/log/openvpn-status.log",
    "verb 4"
  ]

  lines.each do |line|
    system("echo '#{line}' | sudo tee -a #{serverPath}/#{serviceName}.conf > /dev/null")
  end

  system("sudo systemctl enable openvpn-server@#{serviceName}")
  system("sudo systemctl start openvpn-server@#{serviceName}")
end

data = devices_config(vpnNetwork,vpnMask)
puts data

data.each do |device|
  system("sudo touch #{ccdPath}/#{device[:name]}")
  system("echo 'ifconfig-push #{device[:ip]} 255.255.255.0' | sudo tee -a #{ccdPath}/#{device[:name]} > /dev/null")
end

Dir.chdir(openvpnCaPath) do
  data.each do |device|
    system("./easyrsa build-client-full #{device[:name]} nopass")

    clientFile = "#{ovpnFilesPath}/#{device[:name]}.ovpn"

    system("touch #{clientFile}")

    system("echo \"client\" >> #{clientFile}")
    system("echo \"remote #{serviceName} #{vpnPort} #{vpnProtocol}\" >> #{clientFile}")
    system("echo \"dev tun\" >> #{clientFile}")
    system("echo \"<ca>\" >> #{clientFile}")
    system("sudo cat #{serverPath}/ca.crt >> #{clientFile}")
    system("echo \"</ca>\" >> #{clientFile}")
    system("echo \"<key>\" >> #{clientFile}")
    system("cat  pki/private/#{device[:name]}.key >> #{clientFile}")
    system("echo \"</key>\" >> #{clientFile}")
    system("echo \"<cert>\" >> #{clientFile}")
    system("openssl x509 -in pki/issued/#{device[:name]}.crt >> #{clientFile}")
    system("echo \"</cert>\" >> #{clientFile}")
    system("echo \"resolv-retry infinite\" >> #{clientFile}")
    system("echo \"nobind\" >> #{clientFile}")
    system("echo \"persist-key\" >> #{clientFile}")
    system("echo \"persist-tun\" >> #{clientFile}")
    system("echo \"comp-lzo\" >> #{clientFile}")
    system("echo \"verb 4\" >> #{clientFile}")

    system("sudo mkdir -p #{clientPath}/#{device[:name]}")
    system("sudo cp #{clientFile} #{clientPath}/#{device[:name]}/#{device[:name]}.ovpn")
    system("sudo cat #{serverPath}/ca.crt > #{clientPath}/#{device[:name]}/cacert.crt")
    system("sudo cat pki/private/#{device[:name]}.key > #{clientPath}/#{device[:name]}/#{device[:name]}.key")
    system("sudo openssl x509 -in pki/issued/#{device[:name]}.crt > #{clientPath}/#{device[:name]}/#{device[:name]}.crt")

    system("sudo  mv #{clientFile} #{ovpnFilesPath}/#{device[:name]}-#{serviceName}.ovpn")
  end

end

system("sudo chmod 755 #{ccdPath}")
system("sudo chmod 644 #{ccdPath}/*")