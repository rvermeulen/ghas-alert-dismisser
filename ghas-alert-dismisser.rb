require 'bundler/setup'
require 'octokit'
require 'optparse'
require 'optparse/uri'
require 'yaml'
require_relative 'lib/code-scanning.rb'
require_relative 'lib/helpers.rb'

$options = {}
OptionParser.new do |parser|
    parser.banner = "Usage: #{$0} [options] (\"OWNER/REPO[:PATH]\") [(\"OWNER/REPO[:PATH]\") ...])"
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

unless ARGV.any?
    abort("No repositories specified")
end

# First try to load the token from the GH configuration file
github_token = load_gh_token($options[:host].nil? ? "github.com" : $options[:host].host)

unless ENV.include?('GITHUB_TOKEN') || github_token
    abort("The environment variable GITHUB_TOKEN is required")
end

# GITHUB_TOKEN takes precedence over the token otherwise acquired.
github_token = ENV['GITHUB_TOKEN'] if ENV.include?('GITHUB_TOKEN')

Octokit.configure do |c|
    c.access_token = github_token
    c.auto_paginate = true
    c.api_endpoint = "https://#{$options[:host].host}/api/v3/" if $options[:host]
end

$client = Octokit::client

repos = ARGV.map do |repo|
    nwo = if repo.include?(":") then repo.split(":")[0] else repo end
    repo_obj = $client.repo(nwo)
    
    if repo.include?(":")
        path = repo.split(":")[1]

        unless File.exist?(path)
            abort("Path '#{path}' for repository #{nwo} does not exist!")
        end

        unless File.directory?(File.join(path, ".git"))
            abort("Path '#{path}' for repository #{nwo} is not a git repository!")
        end

        repo_obj[:local_path] = path
    end
    repo_obj
end

open_alerts = {}
repos.each do |repo|
    open_alerts[repo] = UsingGhApi::get_alerts($client, repo)
end

open_alerts.each do |repo, alerts|
    alerts.each do |alert|
        def in_repository?(repo, alert)
            if repo.local_path
                UsingGit::in_repository?(repo, alert)
            else
                UsingGhApi::in_repository?($client, repo, alert)
            end
        end
        unless in_repository?(repo, alert)
            puts "Closing #{alert.html_url} because is not in the repository" 
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