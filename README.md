# ApiAuthenticationGem

A lightweight and easy-to-use Ruby gem that adds **user signup and login** functionality to your **Rails API** using **JWT authentication**.

No need to write boilerplate authentication code again — just plug it in, and you're good to go!

---

## ✨ Features

- ✅ User signup with email uniqueness and password validation (handled by the gem)
- ✅ Login with JWT token generation
- ✅ Easy integration with any Rails API
- ✅ Customizable user model support
- ✅ Configurable `secret_key` and `user_class`
- ✅ Tested with RSpec
- ✅ Rails-friendly design

---

## 📦 Installation

Add this line to your Rails application's `Gemfile`:
`gem 'api_authentication_gem'`
Then run:
`bundle install`

🛠 Setup in Your Rails API
1. Add gem configs to your app:
   ```ruby
   # config/initializers/api_authentication_gem.rb

    ApiAuthenticationGem.configure do |config|
      config.secret_key = ENV["SECRET_KEY_BASE"] || "fallback-key" # Always set your secret_key via environment variable in production
      config.user_class = "User"
    end
   ```

2. Generate the User Model (if not already created)
   ```bash
   rails generate model User email:string password_digest:string
   rails db:migrate
   ```

Your User model must use has_secure_password:
  ```ruby
  class User < ApplicationRecord
    has_secure_password
  end
  ```
No need to manually validate emails or handle password_digest — the gem takes care of it internally.

3. Create a Controller to Handle Auth Actions

  ```ruby
  class UsersController < ApplicationController
    def signup
      result = ApiAuthenticationGem::Auth.signup(
        email: params[:email],
        password: params[:password]
      )

      if result[:error]
        render json: { error: result[:error] }, status: :unprocessable_entity
      else
        render json: { message: result[:message], user: result[:user] }, status: :created
      end
    end

    def login
      result = ApiAuthenticationGem::Auth.login(
        email: params[:email],
        password: params[:password]
      )

      if result[:error]
        render json: { error: result[:error] }, status: :unauthorized
      else
        render json: { token: result[:token] }, status: :ok
      end
    end
  end
  ```


3. Define Routes
In your config/routes.rb file:
  ```ruby
    Rails.application.routes.draw do
      post 'signup', to: 'users#signup'
      post 'login', to: 'users#login'
    end
  ```


