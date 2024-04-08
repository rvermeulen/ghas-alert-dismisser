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

module UsingGhApi
    def self.get_alerts(client, repo, state="open", tool_name="CodeQL")
        begin
            client.get_code_scanning_alerts(repo.owner.login, repo.name, {tool_name: tool_name, state: state})
        rescue Octokit::Unauthorized
            STDERR.puts "Unauthorized to access #{repo.full_name}"
            []
        rescue Octokit::NotFound
            STDERR.puts "Unauthorized to access #{repo.full_name}"
            []
        end
    end

    @@cached_trees = {}
    def self.in_repository?(client, repo, alert)
        puts "Checking #{alert.html_url} for path '#{alert.most_recent_instance.location.path}'" if $options.verbose
        location = alert.most_recent_instance.location.path
        unless @@cached_trees.include?(repo)
            @@cached_trees[repo] = {}
        end

        ref = alert.most_recent_instance.ref
        unless @@cached_trees[repo].include?(ref)
            puts "Fetching tree for #{repo.full_name} at #{ref}" if $options.verbose
            tree = client.tree(repo.id, ref)
            puts "Tree #{tree.url} at #{tree.sha}" if $options.verbose
            @@cached_trees[repo][ref] = tree
        end

        tree = @@cached_trees[repo][ref]
        unless tree.tree.index { |object| object.path == location}
            puts "Not found alert location '#{location}'" if $options.verbose
            if location.include?("/")
                puts "Location is part of missing subtree, preparing fetch of subtree" if $options.verbose
                location_parts = location.split("/")
                previous_tree = nil
                previous_tree_full_path = ""
                partial_path = ""
                location_parts.each do |part|
                    partial_path += partial_path != "" ? "/#{part}" : part
                    puts "Checking partial path '#{partial_path}'" if $options.verbose
                    tree_index = tree.tree.index { |object| object.path == partial_path}
                    unless tree_index
                        puts "Not found object for partial path '#{partial_path}'" if $options.verbose
                        if previous_tree
                            puts "Fetching tree for '#{previous_tree.path}'" if $options.verbose
                            subtree = client.tree(repo.id, previous_tree.sha)
                            resolved_subtree = subtree.tree.map { |object| object.path = "#{previous_tree_full_path}/#{object.path}"; object }
                            tree.tree.concat(resolved_subtree)

                            tree_index = tree.tree.index { |object| object.path == partial_path}
                            unless tree_index
                                puts "Nothing found for partial path '#{partial_path}' after fetching '#{previous_tree.path}'" if $options.verbose
                                return false
                            end
                        else
                            puts "Nothing found for partial path '#{partial_path}'" if $options.verbose
                            return false
                        end
                    end

                    object = tree.tree[tree_index]
                    puts "Found object #{object.url} with path #{object.path} for partial path '#{partial_path}'" if $options.verbose

                    if object.type == "tree"
                        previous_tree = object 
                        previous_tree_full_path = partial_path
                    elsif object.type == "blob"
                        return true
                    end
                end
            end
            return false 
        else
            return true
        end
    end

end

module UsingGit
    @@cached_untracked_files = {}
    @@cached_refs = {}
    def self.in_repository?(repo, alert)
        puts "Checking #{repo.git_path} for path '#{alert.most_recent_instance.location.path}'" if $options.verbose
        @@cached_refs[repo] ||= Dir.chdir(repo.git_path) { `git rev-parse --symbolic-full-name HEAD` }.strip
        unless @@cached_refs[repo] == alert.most_recent_instance.ref
            abort "The alert associated with ref #{alert.most_recent_instance.ref} cannot be validated against repository at #{repo.git_path} with ref #{@@cached_refs[repo]}" 
        end
        if File.exist?(File.join(repo.git_path, alert.most_recent_instance.location.path))
            @@cached_untracked_files[repo] ||= Dir.chdir(repo.git_path) { `git ls-files --others` }.lines(chomp: true) 
            if @@cached_untracked_files[repo].include?(alert.most_recent_instance.location.path)
                puts "Found alert location '#{alert.most_recent_instance.location.path}' as untracked file" if $options.verbose
                return false
            else
                puts "Found alert location '#{alert.most_recent_instance.location.path}' as tracked file" if $options.verbose
                return true
            end
        else
            puts "Did not find alert location '#{alert.most_recent_instance.location.path}'" if $options.verbose
            return false
        end
    end
end