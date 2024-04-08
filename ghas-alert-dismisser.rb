require 'bundler/setup'
require 'octokit'
require 'optparse'
require 'optparse/uri'
require 'yaml'
require_relative 'lib/code-scanning.rb'
require_relative 'lib/helpers.rb'

Repo = Struct.new(:nwo, :git_path, :sarif_path, :repo_obj)

class ScriptOptions
    attr_accessor :repos, :verbose, :host, :dry_run

    def initialize
        self.repos= []
        self.verbose = false
        self.host = nil
        self.dry_run = false
    end

    def define_options(parser)
        parser.banner = "Usage: #{$0} [options] (\"OWNER/REPO[:PATH]\") [(\"OWNER/REPO[:PATH]\") ...])"

        parser.on("-g GITHUB_HOST", "--host GITHUB_HOST", URI, "The GitHub host to connect to") do |host|
            self.host = host
        end

        parser.on("-v", "--[no-]verbose", "Run verbosely") do |v|
            self.verbose = v
        end
        
        parser.on("-d", "--[no-]dry-run", "Do a dry run that doesn't perform the action.") do |d|
            self.dry_run = d
        end

        parser.on("-r REPO", "--repo REPO[,(GIT_PATH|SARIF_PATH),(GIT_PATH|SARIF_PATH)]", Array, "The repository in 'owner/repo' format optionally followed by a path to a git directory and/or Sarif file.") do |repo|
            r = Repo.new
            r.nwo = repo.shift
            r.git_path = repo.shift if repo.first && File.directory?(File.join(repo.first, ".git"))
            r.sarif_path= repo.shift if repo.first && File.extname(repo.first) == ".sarif" && File.exist?(repo.first)

            if repo.length > 0
                STDERR.puts "Invalid or non-existing paths #{repo} for repository #{r.nwo}"
                exit 1
            end
                
            self.repos << r 
        end
        
        parser.on("-h", "--help", "Prints this help") do
            puts parser
            exit
        end
    end

    def self.parse(args)
        options = ScriptOptions.new
        args = OptionParser.new do |parser|
            options.define_options(parser)
            parser.parse!(args)
        end
        options
    end
end

$options = ScriptOptions.parse(ARGV)

abort("No repositories specified!") if $options.repos.empty?

# First try to load the token from the GH configuration file
github_token = load_gh_token($options.host.nil? ? "github.com" : $options.host)

unless ENV.include?('GITHUB_TOKEN') || github_token
    abort("The environment variable GITHUB_TOKEN is required")
end

# GITHUB_TOKEN takes precedence over the token otherwise acquired.
github_token = ENV['GITHUB_TOKEN'] if ENV.include?('GITHUB_TOKEN')

Octokit.configure do |c|
    c.access_token = github_token
    c.auto_paginate = true
    c.api_endpoint = "https://#{$options[:host].host}/api/v3/" if $options.host
end

$client = Octokit::client

$options.repos.each do |repo|
    puts "Resolving repository object for #{repo.nwo}" if $options.verbose
    repo.repo_obj = $client.repo(repo.nwo)
end

open_alerts = {}
$options.repos.each do |repo|
    open_alerts[repo] = UsingGhApi::get_alerts($client, repo.repo_obj)
end

open_alerts.each do |repo, alerts|
    alerts.each do |alert|
        def in_repository?(repo, alert)
            if repo.git_path
                UsingGit::in_repository?(repo, alert)
            else
                UsingGhApi::in_repository?($client, repo.repo_obj, alert)
            end
        end
        unless in_repository?(repo, alert)
            puts "Closing #{alert.html_url} because is not in the repository" 
            unless $options.dry_run
                begin
                    $client.update_code_scanning_alerts(repo.repo_obj.owner.login, repo.repo_obj.name, alert.number, "dismissed", {dismissed_reason: "won't fix", dismissed_comment: "This alert's location is not in the repository"})
                rescue Octokit::Unauthorized
                    STDERR.puts "Unauthorized to dismiss alert #{alert.number} in #{repo_obj.full_name}"
                rescue Octokit::NotFound
                    STDERR.puts "Did not find alert #{alert.number} to dismiss in #{repo_obj.full_name}"
                end
            end
        end
    end
end