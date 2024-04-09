require 'bundler/setup'
require 'octokit'
require 'optparse'
require 'optparse/uri'
require 'yaml'
require_relative 'lib/code-scanning.rb'
require_relative 'lib/helpers.rb'

Repo = Struct.new(:nwo, :git_path, :sarif_path, :repo_obj)
Alert = Struct.new(:number, :id, :ref, :path, :url)

class ScriptOptions
    attr_accessor :repos, :verbose, :host, :dry_run, :in_place, :suffix, :backup_ext

    def initialize
        self.repos= []
        self.verbose = false
        self.host = nil
        self.dry_run = false
        self.in_place = false
        self.suffix = "-without-dismissed-alerts"
        self.backup_ext = nil
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

        parser.on("-i", "--in-place [EXTENSION]", "Overwrite the SARIF file with the dismissed alerts.") do |ext|
            self.in_place = true
            self.backup_ext = ext
            self.backup_ext.sub!(/\A\.?(?=.)/, ".")  unless self.backup_ext.nil? # Ensure extension begins with dot.
        end

        parser.on("-s SUFFIX", "--suffix SUFFIX", "The suffix to append to the SARIF file when not in-place.") do |s|
            self.suffix = s
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

alerts_per_repo = {}
$options.repos.each do |repo|
    alerts_per_repo[repo] = UsingGhApi::get_alerts($client, repo.repo_obj) if repo.sarif_path.nil?
    alerts_per_repo[repo] = UsingSarif::get_alerts(repo) if repo.sarif_path
end

alerts_per_repo.each do |repo, alerts|
    alerts_to_dismiss = []
    alerts.each do |alert|
        def in_repository?(repo, alert)
            if repo.git_path
                UsingGit::in_repository?(repo, alert)
            else
                UsingGhApi::in_repository?($client, repo.repo_obj, alert)
            end
        end
        unless in_repository?(repo, alert)
            puts "Dismissing #{alert.path} because is not in the repository" 
            alerts_to_dismiss << alert
        end
    end
    
    unless $options.dry_run
        UsingGhApi::dismiss_alerts($client, repo.repo_obj, alerts_to_dismiss) if repo.sarif_path.nil?
        UsingSarif::dismiss_alerts(repo, alerts_to_dismiss) if repo.sarif_path
    end
end