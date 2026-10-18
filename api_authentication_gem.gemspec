require_relative "lib/api_authentication_gem/version"

Gem::Specification.new do |s|
  s.name        = "api_authentication_gem"
  s.version     = ApiAuthenticationGem::VERSION
  s.summary     = "Production-ready JWT authentication for Rails APIs"
  s.description = "Drop-in JWT signup/login for Rails API apps. Configurable user model, " \
                  "token expiry, password validation, and a ready-made controller concern. " \
                  "See https://github.com/Adarsh-07-Mishra/api_authentication_gem for full docs."
  s.authors     = ["Adarsh Mishra"]
  s.email       = ["aadimishra277@gmail.com"]
  s.files       = Dir["lib/**/*", "README.md", "LICENSE.txt"]
  s.homepage    = "https://github.com/Adarsh-07-Mishra/api_authentication_gem"
  s.license     = "MIT"
  s.required_ruby_version = ">= 2.7.0"

  s.add_dependency "activerecord", ">= 6.0"
  s.add_dependency "activesupport", ">= 6.0"
  s.add_dependency "bcrypt", ">= 3.1"
  s.add_dependency "jwt", ">= 2.0"

  s.add_development_dependency "rspec", ">= 3.0"
  s.add_development_dependency "rspec_junit_formatter"
  s.add_development_dependency "rubocop", "~> 1.65"
  s.add_development_dependency "rubocop-performance", "~> 1.21"
  s.add_development_dependency "rubocop-rspec", "~> 3.0"
  s.add_development_dependency "sqlite3"
end
