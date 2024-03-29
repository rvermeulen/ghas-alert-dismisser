require 'yaml'

def load_gh_token(host)
    hosts_path = File.expand_path("~/.config/gh/hosts.yml")
    if File.exist?(hosts_path) 
        hosts = YAML.load_file(hosts_path)
        if hosts.key?(host)
            hosts[host]["oauth_token"]
        else
            nil
        end
    else
        nil
    end
end