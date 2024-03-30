require 'bundler/setup'
require 'octokit'
require 'optparse'
require 'optparse/uri'
require 'yaml'
require_relative 'lib/code-scanning.rb'
require_relative 'lib/helpers.rb'

$options = {}
OptionParser.new do |parser|
    parser.banner = "Usage: #{$0} [options] \"OWNER/REPO\" [\"OWNER/REPO\" ...]"
    parser.on("-h GITHUB_HOST", "--host GITHUB_HOST", URI, "The GitHub host to connect to") do |host|
        $options[:host] = host
    end
    parser.on("-v", "--verbose", "Run verbosely") do
        $options[:verbose] = true
    end
    
    parser.on("-d", "--dry-run", "Do a dry run that doesn't perform the action.") do
        $options[:dry_run] = true
    end

    parser.on("-h", "--help", "Prints this help") do
        puts parser
        exit
    end
end.parse!

github_token = load_gh_token($options[:host].nil? ? "github.com" : $options[:host].host)

unless ENV.include?('GITHUB_TOKEN') || github_token
    abort("The environment variable GITHUB_TOKEN is required")
end

github_token = ENV['GITHUB_TOKEN'] if ENV.include?('GITHUB_TOKEN')

unless ARGV.any?
    abort("No repositories specified")
end

Octokit.configure do |c|
    c.access_token = github_token
    c.auto_paginate = true
    c.api_endpoint = "https://#{$options[:host].host}/api/v3/" if $options[:host]
end

$client = Octokit::client

repos = ARGV.map do |repo|
    $client.repo(repo)
end

open_alerts = {}
    repos.each do |repo|
        open_alerts[repo] = []
        begin
            $client.get_code_scanning_alerts(repo.owner.login, repo.name, {tool_name: "CodeQL", state: "open"}).each do |alert|
                open_alerts[repo] << alert
            end
        rescue Octokit::Unauthorized
            STDERR.puts "Unauthorized to access #{repo.full_name}"
        rescue Octokit::NotFound
            STDERR.puts "Unauthorized to access #{repo.full_name}"
        end
    end


$cached_trees = {}
def in_repository?(repo, alert)
    puts "Checking #{alert.html_url} for path '#{alert.most_recent_instance.location.path}'" if $options[:verbose]
    location = alert.most_recent_instance.location.path
    unless $cached_trees.include?(repo)
        $cached_trees[repo] = {}
    end

    ref = alert.most_recent_instance.ref
    unless $cached_trees[repo].include?(ref)
        puts "Fetching tree for #{repo.full_name} at #{ref}" if $options[:verbose]
        tree = $client.tree(repo.id, ref)
        puts "Tree #{tree.url} at #{tree.sha}" if $options[:verbose]
        $cached_trees[repo][ref] = tree
    end

    tree = $cached_trees[repo][ref]
    unless tree.tree.index { |object| object.path == location}
        puts "Not found alert location '#{location}'" if $options[:verbose]
        if location.include?("/")
            puts "Location is part of missing subtree, preparing fetch of subtree" if $options[:verbose]
            location_parts = location.split("/")
            previous_tree = nil
            previous_tree_full_path = ""
            partial_path = ""
            location_parts.each do |part|
                partial_path += partial_path != "" ? "/#{part}" : part
                puts "Checking partial path '#{partial_path}'" if $options[:verbose]
                tree_index = tree.tree.index { |object| object.path == partial_path}
                unless tree_index
                    puts "Not found object for partial path '#{partial_path}'" if $options[:verbose]
                    if previous_tree
                        puts "Fetching tree for '#{previous_tree.path}'" if $options[:verbose]
                        subtree = $client.tree(repo.id, previous_tree.sha)
                        resolved_subtree = subtree.tree.map { |object| object.path = "#{previous_tree_full_path}/#{object.path}"; object }
                        tree.tree.concat(resolved_subtree)

                        tree_index = tree.tree.index { |object| object.path == partial_path}
                        unless tree_index
                            puts "Nothing found for partial path '#{partial_path}' after fetching '#{previous_tree.path}'" if $options[:verbose]
                            return false
                        end
                    else
                        puts "Nothing found for partial path '#{partial_path}'" if $options[:verbose]
                        return false
                    end
                end

                object = tree.tree[tree_index]
                puts "Found object #{object.url} with path #{object.path} for partial path '#{partial_path}'" if $options[:verbose]

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

open_alerts.each do |repo, alerts|
    alerts.each do |alert|
        unless in_repository?(repo, alert)
            puts "Closing #{alert.html_url} because is not in the repository" if $options[:verbose]
            unless $options[:dry_run]
                begin
                    $client.update_code_scanning_alerts(repo.owner.login, repo.name, alert.number, "dismissed", {dismissed_reason: "won't fix", dismissed_comment: "This alert's location is not in the repository"})
                rescue Octokit::Unauthorized
                    STDERR.puts "Unauthorized to dismiss alert #{alert.number} in #{repo.full_name}"
                rescue Octokit::NotFound
                    STDERR.puts "Did not find alert #{alert.number} to dismiss in #{repo.full_name}"
                end
            end
        end
    end
end