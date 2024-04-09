require 'fileutils'
require 'json'

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
            client.get_code_scanning_alerts(repo.owner.login, repo.name, {tool_name: tool_name, state: state}).map do |alert|
                res = Alert.new
                res.number = alert.number
                res.path = alert.most_recent_instance.location.path
                res.ref = alert.most_recent_instance.ref
                res.url = alert.html_url
            end
        rescue Octokit::Unauthorized
            abort "Unauthorized to access #{repo.full_name}"
        rescue Octokit::NotFound
            abort "Unauthorized to access #{repo.full_name}"
        end
    end

    @@cached_trees = {}
    def self.in_repository?(client, repo, alert)
        if alert.ref.nil?
            abort "Alert at #{alert.path} has no ref"
        end
        puts "Checking #{alert.url} for path '#{alert.path}'" if $options.verbose && alert.url
        puts "Checking alert on path '#{alert.path}'" if $options.verbose && alert.url.nil?
        unless @@cached_trees.include?(repo)
            @@cached_trees[repo] = {}
        end

        unless @@cached_trees[repo].include?(alert.ref)
            puts "Fetching tree for #{repo.full_name} at #{alert.ref}" if $options.verbose
            tree = client.tree(repo.id, alert.ref)
            puts "Tree #{tree.url} at #{tree.sha}" if $options.verbose
            @@cached_trees[repo][alert.ref] = tree
        end

        tree = @@cached_trees[repo][alert.ref]
        unless tree.tree.index { |object| object.path == alert.path}
            puts "Not found alert path '#{alert.path}'" if $options.verbose
            if location.include?("/")
                puts "Location is part of missing subtree, preparing fetch of subtree" if $options.verbose
                path_parts = alert_path.split("/")
                previous_tree = nil
                previous_tree_full_path = ""
                partial_path = ""
                path_parts.each do |part|
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

    def dismiss_alert(client, repo, alerts)
        begin
            alerts.each do |alert|
                client.update_code_scanning_alerts(repo.owner.login, repo.name, alert.number, "dismissed", {dismissed_reason: "won't fix", dismissed_comment: "This alert's location is not in the repository"})
            end
        rescue Octokit::Unauthorized
            abort "Unauthorized to dismiss alert #{alert.number} in #{repo.full_name}"
        rescue Octokit::NotFound
            abort "Did not find alert #{alert.number} to dismiss in #{repo.full_name}"
        end
    end
end

module UsingGit
    @@cached_untracked_files = {}
    @@cached_refs = {}
    def self.in_repository?(repo, alert)
        puts "Checking #{repo.git_path} for path '#{alert.path}'" if $options.verbose
        @@cached_refs[repo] ||= Dir.chdir(repo.git_path) { `git rev-parse --symbolic-full-name HEAD` }.strip
        unless @@cached_refs[repo] == alert.ref || alert.ref.nil?
            abort "The alert associated with ref #{alert.ref} cannot be validated against repository at #{repo.git_path} with ref #{@@cached_refs[repo]}" 
        end
        if File.exist?(File.join(repo.git_path, alert.path))
            @@cached_untracked_files[repo] ||= Dir.chdir(repo.git_path) { `git ls-files --others` }.lines(chomp: true) 
            if @@cached_untracked_files[repo].include?(alert.path)
                puts "Found alert path '#{alert.path}' as untracked file" if $options.verbose
                return false
            else
                puts "Found alert path '#{alert.path}' as tracked file" if $options.verbose
                return true
            end
        else
            puts "Did not find alert path '#{alert.path}'" if $options.verbose
            return false
        end
    end
end

module UsingSarif
    @@SUPPORTED_SARIF_SCHEMAS = ["https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json", "https://json.schemastore.org/sarif-2.1.0.json"]
    def self.validate!(sarif)
        unless sarif.key?("$schema") && @@SUPPORTED_SARIF_SCHEMAS.include?(sarif["$schema"]) 
            abort "Invalid SARIF file, expected version 2.1.0" 
        end

        unless sarif.key?("runs") && sarif["runs"].is_a?(Array)
            abort "SARIF file does not contain runs"
        end

        unless sarif["runs"].all? do |run| 
            run.key?("tool") && run["tool"].key?("driver") && run["tool"]["driver"].key?("name") && run["tool"]["driver"]["name"] == "CodeQL"
        end
            abort "SARIF file does not contain CodeQL results"
        end
    end

    def self.get_alerts(repo)
        sarif = JSON.load_file(repo.sarif_path)
        validate!(sarif)

        alerts = []
        sarif["runs"].each do |run|
            run["results"].each do |result|
                alert = Alert.new
                alert.id = result["ruleId"]
                alert.path = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
                alerts << alert 
            end
        end
        alerts
    end
    
    def self.dismiss_alerts(repo, alerts)
        sarif = JSON.load_file(repo.sarif_path)
        validate!(sarif)

        sarif["runs"].each do |run|
            run["results"].reject! do |result|
                alerts.any? do |alert|
                    result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == alert.path && result["ruleId"] == alert.id
                end
            end
        end

        if $options.in_place
            FileUtils.mv(repo.sarif_path, "#{repo.sarif_path}#{$options.backup_ext}") unless $options.backup_ext.nil?

            File.open(repo.sarif_path, "w+") do |file|
                file.write(JSON.dump(sarif))
            end
        else
            rewritten_sarif_path = File.join(File.dirname(repo.sarif_path), "#{File.basename(repo.sarif_path, ".sarif")}#{$options.suffix}.sarif")
            File.open(rewritten_sarif_path, "w+") do |file|
                file.write(JSON.dump(sarif))
            end
        end
    end
end