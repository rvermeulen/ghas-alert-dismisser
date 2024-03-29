module Octokit
    class Client
        module CodeScanning
            def get_code_scanning_alerts(owner, repo, options = {})
                get("/repos/#{owner}/#{repo}/code-scanning/alerts", options)
            end
            
            def update_code_scanning_alerts(owner, repo, alert_number, state, options = {})
                options[:state] = state
                patch("/repos/#{owner}/#{repo}/code-scanning/alerts/#{alert_number}", options)
            end
        end
    end
end