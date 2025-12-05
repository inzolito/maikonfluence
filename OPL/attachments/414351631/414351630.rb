#! /opt/local/bin/ruby

# Script openvpn-config-masep-mine.rb
# Versão personalizada do script de configuração OpenVPN

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
  vpn_protocol: "udp",
  force_database_change: false
}

parser = OptionParser.new do |opts|
  opts.banner = "Usage: openvpn-config-masep-mine.rb [options]"

  opts.on("-h", "--help", "Show this help message") do
    puts opts
    exit 0
  end

  opts.on("-d", "--database Database", "Example: jmineops_prod") do |v|
    options[:database] = v
  end

  opts.on("-v", "--devices Devices", "Devices to configure (required)") do |v|
    options[:devices] = v
  end

  opts.on("-s", "--service_name Service Name", "default: ovpn-qa") do |v|
    options[:service_name] = v
  end

  opts.on("-n", "--vpn_network Vpn Network", "default: 10.5.0.0") do |v|
    options[:vpn_network] = v
  end

  opts.on("-m", "--vpn_mask Vpn Mask", "default: 255.255.255.0") do |v|
    options[:vpn_mask] = v
  end

  opts.on("-p", "--vpn_port Vpn Port", "default: 1194") do |v|
    options[:vpn_port] = v
  end

  opts.on("-t", "--vpn_protocol Vpn Protocol", "default: udp") do |v|
    options[:vpn_protocol] = v
  end

  opts.on("-f", "--force-database-change", "Force database changes (optional)") do
    options[:force_database_change] = true
  end

end

begin
  parser.parse!

  if options[:database].nil?
    puts "Error: database parameter is required"
    puts parser
    exit 1
  end

  if options[:devices].nil?
    puts "Error: devices parameter is required"
    puts parser
    exit 1
  end
rescue OptionParser::InvalidOption => e
  puts "Error: #{e}"
  puts parser
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

  # Adiciona um IP à lista de IPs já usados
  def add_used_ip(ip_string)
    begin
      ip = IPAddr.new(ip_string)
      if @rede.include?(ip)
        @ips_usados.add(ip)
        puts "IP #{ip_string} registered as already in use"
      end
    rescue => e
      puts "Invalid IP ignored: #{ip_string} - #{e}"
    end
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

def get_devices_from_database(device_names)
  found_devices = []
  not_found_devices = []

  begin
    if device_names.include?("all")
      sql = "SELECT name, address, netmask FROM devices WHERE address IS NOT NULL AND netmask IS NOT NULL;"
      result = ActiveRecord::Base.connection.execute(sql)
      
      result.each do |row|
        found_devices << {:name => row["name"], :ip => row["address"], :mask => row["netmask"]}
      end
    else
      device_names.each do |device_name|
        sql = "SELECT name, address, netmask FROM devices WHERE name = '#{device_name}';"
        result = ActiveRecord::Base.connection.execute(sql)
        
        if result.count > 0
          row = result.first
          found_devices << {:name => row["name"], :ip => row["address"], :mask => row["netmask"]}
        else
          not_found_devices << device_name
        end
      end
    end
  rescue => e
    $stderr.puts "Database error: #{e}"
    return [], device_names
  end

  return found_devices, not_found_devices
end

def assign_ips_to_devices(devices, network, network_mask, force_update)
  return devices if devices.empty?

  generator = IPGenerator.new(network, network_mask)
  network_range = IPAddr.new("#{network}/#{network_mask}")
  
  # Primeiro, registrar todos os IPs existentes válidos para evitar conflitos
  devices.each do |device|
    if device[:ip] && device[:mask] == network_mask
      begin
        existing_ip = IPAddr.new(device[:ip])
        if network_range.include?(existing_ip)
          generator.add_used_ip(device[:ip])
        end
      rescue
        # IP inválido, será ignorado
      end
    end
  end
  
  devices.each do |device|
    begin
      # Verificar se o device já tem um IP válido na rede correta
      if device[:ip] && device[:mask] == network_mask && !force_update
        begin
          existing_ip = IPAddr.new(device[:ip])
          # Se o IP está na rede correta, manter ele
          if network_range.include?(existing_ip)
            puts "Device #{device[:name]} already has valid IP: #{device[:ip]} - keeping"
            next
          else
            puts "Device #{device[:name]} has IP outside network (#{device[:ip]}) - generating new"
          end
        rescue
          puts "Device #{device[:name]} has invalid IP (#{device[:ip]}) - generating new"
        end
      else
        reason = force_update ? "force update enabled" : "no IP or incorrect mask"
        puts "Device #{device[:name]} #{reason} - generating new"
      end
      
      # Gerar novo IP apenas se necessário
      new_ip = generator.new_ip
      sql = "UPDATE devices SET address = '#{new_ip}', netmask = '#{network_mask}' WHERE name = '#{device[:name]}';"
      ActiveRecord::Base.connection.execute(sql)
      device[:ip] = new_ip
      device[:mask] = network_mask
      puts "Device #{device[:name]} received new IP: #{new_ip}"
    rescue => e
      $stderr.puts "Error updating device #{device[:name]}: #{e}"
    end
  end

  devices
end

#----------------------------------------------------------------------------------

# Parse devices list
device_list = options[:devices].split(',').map(&:strip)

# Database connection
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

# Get devices from database
found_devices, not_found_devices = get_devices_from_database(device_list)

# Show not found devices
unless not_found_devices.empty?
  puts "\n=== DEVICES NOT FOUND IN DATABASE ==="
  not_found_devices.each do |device|
    puts "- #{device}"
  end
end

# Exit if no devices found
if found_devices.empty?
  puts "\nNo devices found to process. Exiting."
  exit 1
end

# Assign IPs if force option is enabled
found_devices = assign_ips_to_devices(found_devices, options[:vpn_network], options[:vpn_mask], options[:force_database_change])

# OpenVPN setup variables
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

# Setup OpenVPN infrastructure (only if it doesn't exist)
unless Dir.exist?("#{openvpnCaPath}/pki")
  puts "Setting up OpenVPN infrastructure..."
  
  # Check if easy-rsa is available
  unless Dir.exist?("/usr/share/easy-rsa") || system("which easyrsa > /dev/null 2>&1")
    puts "Error: easy-rsa not found!"
    puts "Installing easy-rsa..."
    
    unless system("sudo apt-get update && sudo apt-get install -y easy-rsa")
      puts "Failed to install easy-rsa. Please install manually:"
      puts "sudo apt-get install easy-rsa"
      exit 1
    end
    
    puts "easy-rsa installed successfully!"
  end
  
  system("rm -rf #{openvpnCaPath}")
  system("mkdir -p #{openvpnCaPath}")
  system("mkdir -p #{ovpnFilesPath}")
  system("sudo rm -rf #{serverPath}/*")
  system("sudo mkdir -p #{serverPath}")
  system("sudo mkdir -p #{ccdPath}")

  system("sudo systemctl stop openvpn-server@#{serviceName}")
  system("sudo systemctl disable openvpn-server@#{serviceName}")

  Dir.chdir(openvpnCaPath) do
    # Try different easy-rsa locations
    if Dir.exist?("/usr/share/easy-rsa")
      system("cp -r /usr/share/easy-rsa/* .")
    elsif system("which easyrsa > /dev/null 2>&1")
      # If easyrsa is in PATH, use make-cadir if available
      if system("which make-cadir > /dev/null 2>&1")
        system("make-cadir .")
      else
        puts "Error: Cannot setup easy-rsa environment"
        exit 1
      end
    else
      puts "Error: easy-rsa still not found after installation"
      exit 1
    end
    
    # Check if easyrsa script exists
    unless File.exist?("./easyrsa")
      puts "Error: easyrsa script not found in current directory"
      puts "Contents of current directory:"
      system("ls -la")
      exit 1
    end
    
    system("./easyrsa init-pki")

    system("touch pki/.rnd")
    system("chmod 600 pki/.rnd")
    system("openssl rand -out pki/.rnd 256")
    
    # Create CA first
    system("./easyrsa --batch build-ca nopass")
    
    # Generate DH parameters
    system("./easyrsa gen-dh")
    
    # Generate server certificate and sign it
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
  
  puts "OpenVPN infrastructure setup completed."
end

generated_devices = []

# Generate certificates only for found devices
found_devices.each do |device|
  next if device[:ip].nil? || device[:ip].empty?
  
  puts "Processing device: #{device[:name]}"
  
  # Setup CCD for device
  system("sudo touch #{ccdPath}/#{device[:name]}")
  system("echo 'ifconfig-push #{device[:ip]} #{options[:vpn_mask]}' | sudo tee #{ccdPath}/#{device[:name]} > /dev/null")

  # Ensure we're in the right directory and it exists
  if Dir.exist?(openvpnCaPath)
    Dir.chdir(openvpnCaPath) do
      # Check if certificate already exists
      unless File.exist?("pki/issued/#{device[:name]}.crt")
        puts "Generating certificate for #{device[:name]}..."
        system("./easyrsa build-client-full #{device[:name]} nopass")
      else
        puts "Certificate already exists for #{device[:name]}"
      end

      clientFile = "#{ovpnFilesPath}/#{device[:name]}.ovpn"
      
      # Check if required files exist before proceeding
      if File.exist?("pki/issued/#{device[:name]}.crt") && File.exist?("pki/private/#{device[:name]}.key")
        # Generate .ovpn file
        system("touch #{clientFile}")
        system("echo \"client\" > #{clientFile}")
        system("echo \"remote #{host} #{vpnPort} #{vpnProtocol}\" >> #{clientFile}")
        system("echo \"dev tun\" >> #{clientFile}")
        system("echo \"<ca>\" >> #{clientFile}")
        system("sudo cat #{serverPath}/ca.crt >> #{clientFile}")
        system("echo \"</ca>\" >> #{clientFile}")
        system("echo \"<key>\" >> #{clientFile}")
        system("cat pki/private/#{device[:name]}.key >> #{clientFile}")
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

        # Copy files to client directory
        system("sudo mkdir -p #{clientPath}/#{device[:name]}")
        system("sudo cp #{clientFile} #{clientPath}/#{device[:name]}/#{device[:name]}.ovpn")
        system("sudo cp #{serverPath}/ca.crt #{clientPath}/#{device[:name]}/cacert.crt")
        system("sudo cp pki/private/#{device[:name]}.key #{clientPath}/#{device[:name]}/#{device[:name]}.key")
        system("sudo openssl x509 -in pki/issued/#{device[:name]}.crt -out #{clientPath}/#{device[:name]}/#{device[:name]}.crt")

        # Move final .ovpn file
        system("sudo mv #{clientFile} #{ovpnFilesPath}/#{device[:name]}-#{serviceName}.ovpn")
        
        generated_devices << device
        puts "Certificate generated successfully for #{device[:name]}"
      else
        puts "Error: Required certificate files not found for #{device[:name]}"
      end
    end
  else
    puts "Error: OpenVPN CA directory not found"
  end
end

# Set permissions
system("sudo chmod 755 #{ccdPath}")
ccd_files = Dir.glob("#{ccdPath}/*")
system("sudo chmod 644 #{ccdPath}/*") unless ccd_files.empty?

# Show results
puts "\n=== CERTIFICATES GENERATED FOR ==="
generated_devices.each do |device|
  puts "- #{device[:name]} (IP: #{device[:ip]})"
end

puts "\n=== SUMMARY ==="
puts "Total devices processed: #{generated_devices.size}"
puts "Devices not found: #{not_found_devices.size}"
puts "Database updates: #{options[:force_database_change] ? 'ENABLED' : 'DISABLED'}"
