# api_authentication_gem

A Ruby gem that handles JWT authentication for Rails APIs. It covers the usual stuff — signup, login, refresh tokens, password reset, lockout — plus some extras like magic links, RBAC, session tracking, hooks, and RS256.

[![Gem Version](https://badge.fury.io/rb/api_authentication_gem.svg)](https://rubygems.org/gems/api_authentication_gem)

---

## What's included

- Signup and login with JWT
- Refresh tokens (rotated on every use)
- Token revocation
- Password reset
- Account lockout after failed attempts
- `authenticate_user!` controller concern
- Role-based access control
- Passwordless magic link login
- Per-device session tracking
- Hooks for auth events (signup, login, logout, etc.)
- RS256 support (asymmetric keys)

---

## Installation

```ruby
# Gemfile
gem 'api_authentication_gem'
```

```bash
bundle install
```

---

## Database migration

Run this migration once. You only need the tables for the features you actually use.

```ruby
class CreateApiAuthTables < ActiveRecord::Migration[7.0]
  def change
    create_table :api_auth_refresh_tokens do |t|
      t.integer  :user_id,    null: false
      t.string   :token,      null: false
      t.datetime :expires_at, null: false
      t.datetime :revoked_at
      t.timestamps
    end
    add_index :api_auth_refresh_tokens, :token,   unique: true
    add_index :api_auth_refresh_tokens, :user_id

    create_table :api_auth_revoked_tokens do |t|
      t.string   :jti,        null: false
      t.datetime :expires_at, null: false
      t.timestamps
    end
    add_index :api_auth_revoked_tokens, :jti, unique: true

    create_table :api_auth_password_resets do |t|
      t.string   :identifier, null: false
      t.string   :token,      null: false
      t.datetime :expires_at, null: false
      t.datetime :used_at
      t.timestamps
    end
    add_index :api_auth_password_resets, :token,      unique: true
    add_index :api_auth_password_resets, :identifier

    create_table :api_auth_lockouts do |t|
      t.string   :identifier,      null: false
      t.integer  :failed_attempts, default: 0, null: false
      t.datetime :locked_until
      t.timestamps
    end
    add_index :api_auth_lockouts, :identifier, unique: true

    # only needed if you use magic links
    create_table :api_auth_magic_links do |t|
      t.string   :identifier, null: false
      t.string   :token,      null: false
      t.datetime :expires_at, null: false
      t.datetime :used_at
      t.timestamps
    end
    add_index :api_auth_magic_links, :token,      unique: true
    add_index :api_auth_magic_links, :identifier

    # only needed if you use session tracking
    create_table :api_auth_sessions do |t|
      t.integer  :user_id,    null: false
      t.string   :jti,        null: false
      t.string   :ip_address
      t.string   :user_agent
      t.datetime :expires_at, null: false
      t.datetime :revoked_at
      t.timestamps
    end
    add_index :api_auth_sessions, :jti,     unique: true
    add_index :api_auth_sessions, :user_id
  end
end
```

```bash
rails db:migrate
```

---

## Setup

### 1. Initializer

```ruby
# config/initializers/api_auth.rb

ApiAuthenticationGem.configure do |config|
  config.secret_key = ENV["API_AUTH_SECRET_KEY"]

  config.user_class             = "User"
  config.token_expiry           = 15 * 60       # 15 min
  config.min_password_length    = 8

  config.refresh_tokens_enabled = true
  config.refresh_token_expiry   = 30 * 24 * 60 * 60  # 30 days

  config.revocation_enabled     = true

  config.lockout_enabled        = true
  config.max_login_attempts     = 5
  config.lockout_duration       = 15 * 60

  # optional features
  config.magic_link_enabled       = false
  config.session_tracking_enabled = false

  # hooks — all optional
  config.on_signup         = ->(user)  { puts "signed up: #{user.email}" }
  config.on_login          = ->(user)  { puts "logged in: #{user.email}" }
  config.on_login_failure  = ->(email) { puts "failed login: #{email}" }
  config.on_logout         = ->(jti)   { puts "logged out: #{jti}" }
  config.on_password_reset = ->(user)  { puts "password reset: #{user.email}" }
end
```

### 2. User model

```bash
rails generate model User email:string:uniq password_digest:string role:string
rails db:migrate
```

```ruby
class User < ApplicationRecord
  has_secure_password
  validates :email, presence: true, uniqueness: true
end
```

### 3. Auth controller

```ruby
class AuthController < ApplicationController
  def signup
    result = ApiAuthenticationGem::Auth.signup(email: params[:email], password: params[:password])
    if result[:error]
      render json: result, status: :unprocessable_entity
    else
      render json: result, status: :created
    end
  end

  def login
    result = ApiAuthenticationGem::Auth.login(
      email:      params[:email],
      password:   params[:password],
      ip_address: request.remote_ip,
      user_agent: request.user_agent
    )
    result[:error] ? render(json: result, status: :unauthorized) : render(json: result)
  end

  def refresh
    result = ApiAuthenticationGem::Auth.refresh(refresh_token: params[:refresh_token])
    result[:error] ? render(json: result, status: :unauthorized) : render(json: result)
  end

  def logout
    token = request.headers["Authorization"]&.split(" ")&.last
    render json: ApiAuthenticationGem::Auth.revoke(token: token)
  end

  def forgot_password
    result = ApiAuthenticationGem::Auth.request_password_reset(email: params[:email])
    # send result[:reset_token] by email — don't expose it in the response
    render json: { message: result[:message] }
  end

  def reset_password
    result = ApiAuthenticationGem::Auth.reset_password(
      reset_token:  params[:token],
      new_password: params[:password]
    )
    result[:error] ? render(json: result, status: :unprocessable_entity) : render(json: result)
  end

  # magic links
  def send_magic_link
    result = ApiAuthenticationGem::Auth.send_magic_link(email: params[:email])
    # send result[:magic_token] by email — don't expose it in the response
    render json: { message: result[:message] }
  end

  def verify_magic_link
    result = ApiAuthenticationGem::Auth.verify_magic_link(token: params[:token])
    result[:error] ? render(json: result, status: :unauthorized) : render(json: result)
  end

  # session tracking
  def sessions
    authenticate_user!
    render json: ApiAuthenticationGem::Auth.active_sessions(user_id: @current_user.id)
  end

  def revoke_session
    authenticate_user!
    render json: ApiAuthenticationGem::Auth.revoke_session(jti: params[:jti])
  end

  def revoke_all_sessions
    authenticate_user!
    render json: ApiAuthenticationGem::Auth.revoke_all_sessions(user_id: @current_user.id)
  end
end
```

### 4. Routes

```ruby
Rails.application.routes.draw do
  post   "signup",             to: "auth#signup"
  post   "login",              to: "auth#login"
  post   "refresh",            to: "auth#refresh"
  delete "logout",             to: "auth#logout"
  post   "forgot_password",    to: "auth#forgot_password"
  post   "reset_password",     to: "auth#reset_password"
  post   "magic_link",         to: "auth#send_magic_link"
  post   "magic_link/verify",  to: "auth#verify_magic_link"
  get    "sessions",           to: "auth#sessions"
  delete "sessions/:jti",      to: "auth#revoke_session"
  delete "sessions",           to: "auth#revoke_all_sessions"
end
```

---

## Protecting routes

Include the concern and call `authenticate_user!`:

```ruby
class ApplicationController < ActionController::API
  include ApiAuthenticationGem::Concerns::Authenticatable
end

class PostsController < ApplicationController
  before_action :authenticate_user!

  def index
    render json: current_user.posts
  end
end
```

---

## RBAC

Add a `role` column to users, then use `authorize_role!` inside any action:

```ruby
class AdminController < ApplicationController
  before_action :authenticate_user!
  before_action -> { authorize_role!("admin") }

  def dashboard
    render json: { message: "welcome #{current_user.email}" }
  end
end
```

Returns HTTP 403 if the role doesn't match:

```json
{ "error": "Forbidden", "required": ["admin"], "current": "viewer" }
```

---

## Magic links

```ruby
# step 1 — request a link
result = ApiAuthenticationGem::Auth.send_magic_link(email: "user@example.com")
# deliver result[:magic_token] by email

# step 2 — user clicks the link
result = ApiAuthenticationGem::Auth.verify_magic_link(token: params[:token])
# => { token: "...", user: ..., refresh_token: "..." }
```

Tokens are single-use. Requesting a new one invalidates the previous one.

---

## Session tracking

```ruby
# list active sessions
ApiAuthenticationGem::Auth.active_sessions(user_id: user.id)

# revoke one session (sign out a specific device)
ApiAuthenticationGem::Auth.revoke_session(jti: "some-jti")

# sign out everywhere
ApiAuthenticationGem::Auth.revoke_all_sessions(user_id: user.id)
```

---

## RS256

If you want asymmetric keys instead of a shared secret:

```bash
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -pubout -out public.pem
```

```ruby
ApiAuthenticationGem.configure do |config|
  config.algorithm   = "RS256"
  config.private_key = OpenSSL::PKey::RSA.new(File.read("private.pem"))
  config.public_key  = OpenSSL::PKey::RSA.new(File.read("public.pem"))
  config.user_class  = "User"
end
```

---

## Method reference

### `Auth.signup(email:, password:)`
| Result | Keys |
|---|---|
| Success | `message`, `user`, `token`, `refresh_token` |
| Blank email | `error: "Email is required"` |
| Weak password | `error: "Password must be at least N characters"` |
| Duplicate email | `error: "Email has already been taken"` |

### `Auth.login(email:, password:, ip_address: nil, user_agent: nil)`
| Result | Keys |
|---|---|
| Success | `token`, `user`, `refresh_token` |
| Wrong credentials | `error: "Invalid email or password"` |
| Locked | `error: "Account locked. Try again in N minute(s)."` |

### `Auth.refresh(refresh_token:)`
| Result | Keys |
|---|---|
| Success | `token`, `refresh_token`, `user` |
| Expired | `error: "Refresh token has expired"` |
| Revoked | `error: "Refresh token has been revoked"` |

### `Auth.revoke(token:)`
| Result | Keys |
|---|---|
| Success | `message: "Token revoked successfully"` |
| Invalid | `error: "Invalid token"` |

### `Auth.request_password_reset(email:)`
Returns `{ message:, reset_token: }` for known emails, same message for unknown ones (no enumeration).

### `Auth.reset_password(reset_token:, new_password:)`
| Result | Keys |
|---|---|
| Success | `message: "Password has been reset successfully"` |
| Bad token | `error: "Invalid or expired reset token"` |

### `Auth.send_magic_link(email:)`
Returns `{ message:, magic_token: }` for known emails, same message for unknown ones.

### `Auth.verify_magic_link(token:)`
| Result | Keys |
|---|---|
| Success | `token`, `user`, `refresh_token` |
| Bad token | `error: "Invalid or expired magic link"` |

### `Auth.active_sessions(user_id:)` / `Auth.revoke_session(jti:)` / `Auth.revoke_all_sessions(user_id:)`
All return `{ error: }` when `session_tracking_enabled` is false.

### `Auth.decode(token)`
Returns the JWT payload hash, or `nil` if invalid/expired/revoked.

---

## JWT claims

| Claim | Value |
|---|---|
| `sub` | User ID |
| `iat` | Issued at |
| `exp` | Expires at |
| `jti` | Unique token ID |

---

## Cron cleanup

```ruby
ApiAuthenticationGem::RevokedToken.cleanup!
```

Run this periodically to prune expired entries from the revoked tokens table.

---

## Running tests

```bash
bundle exec rspec
# 186 examples, 0 failures
```

---

## License

MIT
