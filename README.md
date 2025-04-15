# ApiAuthenticationGem

A lightweight and easy-to-use Ruby gem that adds **user signup and login** functionality to your **Rails API** using **JWT authentication**.

No need to write boilerplate authentication code again — just plug it in, and you're good to go!

---

## ✨ Features

- ✅ User signup with email uniqueness and password validation (handled by the gem)
- ✅ Login with JWT token generation
- ✅ Easy integration with any Rails API
- ✅ Customizable user model support

---

## 📦 Installation

Add this line to your Rails application's `Gemfile`:
gem 'api_authentication_gem'
Then run:
bundle install

🛠 Setup in Your Rails API
1. Generate the User Model (if not already created)
rails generate model User email:string password_digest:string
rails db:migrate

2. Create a Controller to Handle Auth Actions

class UsersController < ApplicationController
  def signup
    result = ApiAuthenticationGem::Auth.signup(
      email: params[:email],
      password: params[:password],
      user_class: User
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
      password: params[:password],
      user_class: User
    )

    if result[:error]
      render json: { error: result[:error] }, status: :unauthorized
    else
      render json: { token: result[:token] }, status: :ok
    end
  end
end


3. Define Routes
In your config/routes.rb file:
Rails.application.routes.draw do
  post 'signup', to: 'users#signup'
  post 'login', to: 'users#login'
end


