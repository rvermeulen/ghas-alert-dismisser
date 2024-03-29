require 'bundler/setup'
require 'octokit'
require 'optparse'
require 'optparse/uri'
require 'yaml'
require_relative 'lib/code-scanning.rb'
require_relative 'lib/helpers.rb'

$options = {}
OptionParser.new do |parser|
    parser.banner = "Usage: app.rb [options] \"OWNER/REPO\" [\"OWNER/REPO\" ...]"
    parser.on("-h GITHUB_HOST", "--host GITHUB_HOST", URI, "The GitHub host to connect to") do |host|
        $options[:host] = host
    end
    parser.on("-v", "--verbose", "Run verbosely") do
        $options[:verbose] = true
    end
    
    parser.on("-d", "--dry-run", "Do a dry run that doesn't perform the action.") do
        $options[:verbose] = true
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
    location = alert.most_recent_instance.location.path
    unless $cached_trees.include?(repo)
        $cached_trees[repo] = {}
    end

    ref = alert.most_recent_instance.ref
    unless $cached_trees[repo].include?(ref)
        $cached_trees[repo][ref] = $client.tree(repo.id, ref, :recursive => true)
    end

    tree = $cached_trees[repo][ref]
    unless tree.tree.index { |object| object.path == location}
        unless tree.truncated
            puts "Fetching full tree for #{repo.full_name} at #{ref}" if $options[:verbose]
            location_parts = location.split("/")
            previous_tree = nil
            location_parts.each do |part|
                tree_index = tree.tree.index { |object| object.path == part}
                unless tree_index
                    puts "Not found in #{location} at part #{part}" if $options[:verbose]
                    if previous_tree
                        puts "Fetching tree for #{previous_tree.path}" if $options[:verbose]
                        subtree = $client.tree(repo.id, previous_tree.sha, :recursive => true)
                        $cached_trees[repo][ref].tree.concat(subtree.tree)
                        
                        tree_index = tree.tree.index { |object| object.path == part}
                        unless tree_index
                            puts "Nothing found for #{part} after fetching #{previous_tree.path}" if $options[:verbose]
                            return false
                        end
                    else
                        puts "Nothing found for #{part}" if $options[:verbose]
                        return false
                    end
                end

                object = tree.tree[tree_index]

                if object.type == "tree"
                    previous_tree = object 
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
            puts "Closing #{alert.rule.id} in #{repo.full_name} because #{alert.most_recent_instance.location.path} is not in the repository" if $options[:verbose]
            unless $options[:dry_run]
                begin
                    $client.update_code_scanning_alerts(repo.owner.login, repo.name, alert.number, "dismissed", {dismissed_reason: "won't fix", dismissed_comment: "This alert's location is not in the repository"})
                rescue Octokit::Unauthorized
                    STDERR.puts "Unauthorized to dismiss alert #{alert.number} in #{repo.full_name}"
                rescue Octokit::NotFound
                    STDERR.puts "Did not find alert #{alert_number} to update dismiss in #{repo.full_name}"
                end
            end
        end
    end
end