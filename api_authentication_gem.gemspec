Gem::Specification.new do |s|
    s.name        = "api_authentication_gem"
    s.version     = "0.1.4"
    s.summary     = "Provides JWT-based signup and login for APIs"
    s.description = "Reusable gem for authentication with user-defined models. For detailed usage, visit: https://github.com/Adarsh-07-Mishra/api_authentication_gem/blob/main/README.md"
    s.authors     = ["Adarsh Mishra"]
    s.email       = ["aadimishra24@gmail.com"]
    s.files       = Dir["lib/**/*", "README.md"]
    s.homepage    = "https://github.com/Adarsh-07-Mishra/api_authentication_gem"
    s.license     = "MIT"
  
    s.add_dependency "bcrypt"
    s.add_dependency "jwt"
    s.add_development_dependency "rspec"
    s.add_development_dependency "rspec-rails"
  end
  