Gem::Specification.new do |s|
    s.name        = "api_authentication_gem"
    s.version     = "0.1.1"
    s.summary     = "Provides JWT-based signup and login for APIs"
    s.description = "Reusable gem for authentication with user-defined models"
    s.authors     = ["Adarsh Mishra"]
    s.email       = ["aadimishra24@gmail.com"]
    s.files       = Dir["lib/**/*", "README.md"]
    s.homepage    = "https://rubygems.org/gems/api_authentication_gem"
    s.license     = "MIT"
  
    s.add_dependency "bcrypt"
    s.add_dependency "jwt"
  end
  