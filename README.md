# ApiAuthenticationGem

A production-ready Ruby gem that adds **JWT-based authentication** to any Rails API — signup, login, refresh tokens, token revocation, password reset, account lockout, magic links, RBAC, session tracking, event hooks, and RS256 support — zero boilerplate required.

[![Gem Version](https://badge.fury.io/rb/api_authentication_gem.svg)](https://rubygems.org/gems/api_authentication_gem)

---

## Features

| Feature | Status |
|---|---|
| Signup with email + password validation | ✅ |
| Login with JWT access token (HS256 / RS256) | ✅ |
| JWT with `exp`, `iat`, `jti` claims | ✅ |
| Refresh tokens (30-day, rotated on use) | ✅ |
| Token revocation / immediate logout | ✅ |
| Password reset flow | ✅ |
| Account lockout after N failed attempts | ✅ |
| `Authenticatable` concern for controllers | ✅ |
| Role-based access control (RBAC) | ✅ |
| Passwordless login via magic links | ✅ |
| Active session tracking per device | ✅ |
| Auth event hooks (signup, login, logout, …) | ✅ |
| RS256 asymmetric JWT signing | ✅ |
| Fully configurable user model + field names | ✅ |
| RSpec test suite — 186 examples, 0 failures | ✅ |

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

## Database Migration

Copy this migration into your Rails app and run `rails db:migrate`. Add only the tables you need — each feature checks whether its table exists.

```ruby
# db/migrate/YYYYMMDD_create_api_auth_tables.rb
class CreateApiAuthTables < ActiveRecord::Migration[7.0]
  def change
    # ---- Core Tier 1 tables ----------------------------------------

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

    # ---- Tier 2 tables (enable features as needed) -----------------

    # Magic links (config.magic_link_enabled = true)
    create_table :api_auth_magic_links do |t|
      t.string   :identifier, null: false
      t.string   :token,      null: false
      t.datetime :expires_at, null: false
      t.datetime :used_at
      t.timestamps
    end
    add_index :api_auth_magic_links, :token,      unique: true
    add_index :api_auth_magic_links, :identifier

    # Session tracking (config.session_tracking_enabled = true)
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

---

## Setup

### 1. Create an initializer

```ruby
# config/initializers/api_authentication_gem.rb

ApiAuthenticationGem.configure do |config|
  # ---- Required -------------------------------------------------------
  config.secret_key = ENV["API_AUTH_SECRET_KEY"]   # never hardcode in production

  # ---- Core (optional, defaults shown) --------------------------------
  config.user_class             = "User"
  config.email_attribute        = :email
  config.password_attribute     = :password
  config.identifier             = :email
  config.password_verify_method = :authenticate    # bcrypt via has_secure_password
  config.token_expiry           = 15 * 60          # access token: 15 minutes
  config.min_password_length    = 8

  # ---- Refresh tokens -------------------------------------------------
  config.refresh_tokens_enabled = true
  config.refresh_token_expiry   = 30 * 24 * 60 * 60  # 30 days

  # ---- Token revocation -----------------------------------------------
  config.revocation_enabled     = true

  # ---- Password reset -------------------------------------------------
  config.password_reset_expiry  = 15 * 60          # reset token: 15 minutes

  # ---- Account lockout ------------------------------------------------
  config.lockout_enabled        = true
  config.max_login_attempts     = 5
  config.lockout_duration       = 15 * 60          # lock for 15 minutes

  # ---- Role-based access control (Tier 2) -----------------------------
  # Column on your User model that holds the role string/symbol
  config.role_attribute         = :role            # default

  # ---- Magic links / passwordless login (Tier 2) ----------------------
  config.magic_link_enabled     = false
  config.magic_link_expiry      = 15 * 60          # 15 minutes

  # ---- Active session tracking (Tier 2) -------------------------------
  config.session_tracking_enabled = false

  # ---- Auth event hooks (Tier 2) --------------------------------------
  config.on_signup        = ->(user)  { Rails.logger.info "New signup: #{user.email}" }
  config.on_login         = ->(user)  { Rails.logger.info "Login: #{user.email}" }
  config.on_login_failure = ->(email) { Rails.logger.warn "Failed login: #{email}" }
  config.on_logout        = ->(jti)   { Rails.logger.info "Logout jti=#{jti}" }
  config.on_password_reset = ->(user) { Rails.logger.info "Password reset: #{user.email}" }

  # ---- RS256 asymmetric JWT (Tier 2, alternative to HS256) ------------
  # config.algorithm   = "RS256"
  # config.private_key = OpenSSL::PKey::RSA.new(File.read(ENV["RSA_PRIVATE_KEY_PATH"]))
  # config.public_key  = OpenSSL::PKey::RSA.new(File.read(ENV["RSA_PUBLIC_KEY_PATH"]))
end
```

> `configure` calls `validate!` automatically and raises `ConfigurationError` at boot if any required value is missing or invalid.

---

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

---

### 3. Auth controller

```ruby
class AuthController < ApplicationController
  def signup
    result = ApiAuthenticationGem::Auth.signup(
      email:    params[:email],
      password: params[:password]
    )
    if result[:error]
      render json: { error: result[:error] }, status: :unprocessable_entity
    else
      render json: {
        message:       result[:message],
        token:         result[:token],
        refresh_token: result[:refresh_token]
      }, status: :created
    end
  end

  def login
    result = ApiAuthenticationGem::Auth.login(
      email:      params[:email],
      password:   params[:password],
      ip_address: request.remote_ip,       # optional — stored in session record
      user_agent: request.user_agent       # optional — stored in session record
    )
    if result[:error]
      render json: { error: result[:error] }, status: :unauthorized
    else
      render json: { token: result[:token], refresh_token: result[:refresh_token] }
    end
  end

  def refresh
    result = ApiAuthenticationGem::Auth.refresh(
      refresh_token: params[:refresh_token]
    )
    if result[:error]
      render json: { error: result[:error] }, status: :unauthorized
    else
      render json: { token: result[:token], refresh_token: result[:refresh_token] }
    end
  end

  def logout
    result = ApiAuthenticationGem::Auth.revoke(
      token: request.headers["Authorization"]&.split(" ")&.last
    )
    if result[:error]
      render json: { error: result[:error] }, status: :unprocessable_entity
    else
      render json: { message: result[:message] }
    end
  end

  def forgot_password
    result = ApiAuthenticationGem::Auth.request_password_reset(
      email: params[:email]
    )
    # Deliver result[:reset_token] via email — never expose it in the API response
    render json: { message: result[:message] }
  end

  def reset_password
    result = ApiAuthenticationGem::Auth.reset_password(
      reset_token:  params[:token],
      new_password: params[:password]
    )
    if result[:error]
      render json: { error: result[:error] }, status: :unprocessable_entity
    else
      render json: { message: result[:message] }
    end
  end

  # ---- Magic link endpoints (enable config.magic_link_enabled = true) ----

  def send_magic_link
    result = ApiAuthenticationGem::Auth.send_magic_link(email: params[:email])
    # Deliver result[:magic_token] via email — never expose it in the API response
    render json: { message: result[:message] }
  end

  def verify_magic_link
    result = ApiAuthenticationGem::Auth.verify_magic_link(token: params[:token])
    if result[:error]
      render json: { error: result[:error] }, status: :unauthorized
    else
      render json: { token: result[:token], refresh_token: result[:refresh_token] }
    end
  end

  # ---- Session tracking endpoints (enable config.session_tracking_enabled = true) ----

  def active_sessions
    result = ApiAuthenticationGem::Auth.active_sessions(user_id: current_user.id)
    render json: result
  end

  def revoke_session
    result = ApiAuthenticationGem::Auth.revoke_session(jti: params[:jti])
    if result[:error]
      render json: { error: result[:error] }, status: :unprocessable_entity
    else
      render json: { message: result[:message] }
    end
  end

  def revoke_all_sessions
    result = ApiAuthenticationGem::Auth.revoke_all_sessions(user_id: current_user.id)
    render json: { message: result[:message] }
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

  # Magic link (Tier 2)
  post   "magic_link",         to: "auth#send_magic_link"
  post   "magic_link/verify",  to: "auth#verify_magic_link"

  # Session management (Tier 2)
  get    "sessions",           to: "auth#active_sessions"
  delete "sessions/:jti",      to: "auth#revoke_session"
  delete "sessions",           to: "auth#revoke_all_sessions"
end
```

---

## Protecting routes

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

`authenticate_user!` reads the `Authorization` header (`Bearer <token>`), decodes the JWT, checks the revocation blocklist, sets `@current_user`, and renders HTTP 401 automatically on any failure.

---

## Role-Based Access Control (RBAC)

Add a `role` column to your users table (or configure `config.role_attribute` to point to an existing column). Then call `authorize_role!` inside any controller action:

```ruby
class AdminController < ApplicationController
  before_action :authenticate_user!
  before_action -> { authorize_role!("admin") }

  def dashboard
    render json: { data: "admin only" }
  end
end

class ContentController < ApplicationController
  before_action :authenticate_user!

  def publish
    authorize_role!("admin", "editor")
    # only admins and editors reach here
  end
end
```

On failure `authorize_role!` renders HTTP 403:

```json
{ "error": "Forbidden", "required": ["admin"], "current": "viewer" }
```

---

## Magic Links (Passwordless Login)

Enable the feature and add the `api_auth_magic_links` table, then use the two-step flow:

**Step 1 — request a link (send this token by email)**

```ruby
result = ApiAuthenticationGem::Auth.send_magic_link(email: "user@example.com")
# => { message: "If that email is registered, a magic link has been sent.",
#      magic_token: "abc123..." }   # deliver this via email, never expose in response
```

**Step 2 — verify the link (user clicks the link)**

```ruby
result = ApiAuthenticationGem::Auth.verify_magic_link(token: params[:token])
# => { token: "<jwt>", refresh_token: "...", user: <User> }
```

- Tokens are single-use — replayed tokens return an error.
- Each new `send_magic_link` call invalidates any previous unused token for that email.
- Both known and unknown email addresses return the same message to prevent enumeration.

---

## Session Tracking

Enable the feature and add the `api_auth_sessions` table. Every `signup` and `login` call will then create an `AuthSession` record.

```ruby
# Log in with device metadata
result = ApiAuthenticationGem::Auth.login(
  email:      "user@example.com",
  password:   "secret",
  ip_address: request.remote_ip,
  user_agent: request.user_agent
)

# List active sessions for a user
result = ApiAuthenticationGem::Auth.active_sessions(user_id: user.id)
# => { sessions: [<AuthSession>, ...] }

# Revoke a specific session (e.g. "sign out this device")
result = ApiAuthenticationGem::Auth.revoke_session(jti: "some-jti-uuid")
# => { message: "Session revoked successfully" }

# Sign out everywhere
result = ApiAuthenticationGem::Auth.revoke_all_sessions(user_id: user.id)
# => { message: "3 session(s) revoked" }
```

`revoke_session` and `revoke_all_sessions` also add the JTI(s) to the revocation blocklist when `revocation_enabled` is `true`, so the corresponding access tokens are invalidated immediately.

---

## Auth Event Hooks

Hooks let you react to auth events without monkey-patching — useful for audit logs, analytics, welcome emails, or Slack alerts. All hooks receive a single argument and are called synchronously. Any exception raised inside a hook is rescued and swallowed so it never breaks the auth flow.

```ruby
ApiAuthenticationGem.configure do |config|
  config.on_signup        = ->(user)  { WelcomeMailer.send(user).deliver_later }
  config.on_login         = ->(user)  { AuditLog.record(:login, user) }
  config.on_login_failure = ->(email) { SlackAlert.warn("Failed login: #{email}") }
  config.on_logout        = ->(jti)   { AuditLog.record(:logout, jti: jti) }
  config.on_password_reset = ->(user) { AuditLog.record(:password_reset, user) }
end
```

| Hook | Argument | Called when |
|---|---|---|
| `on_signup` | `User` | Signup succeeds |
| `on_login` | `User` | Password login or magic link verify succeeds |
| `on_login_failure` | `email` (String) | Wrong password or unknown email |
| `on_logout` | `jti` (String) | Token revoked successfully |
| `on_password_reset` | `User` | Password reset completes |

---

## RS256 Asymmetric JWT

Switch from the default HS256 (shared secret) to RS256 (RSA key pair). Useful when your resource servers need to verify tokens without accessing the secret key.

**Generate a key pair:**

```bash
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -pubout -out public.pem
```

**Configure the gem:**

```ruby
ApiAuthenticationGem.configure do |config|
  config.algorithm   = "RS256"
  config.private_key = OpenSSL::PKey::RSA.new(File.read("private.pem"))
  config.public_key  = OpenSSL::PKey::RSA.new(File.read("public.pem"))
  config.user_class  = "User"
  # secret_key is not required for RS256
end
```

**Verify a token independently (on a resource server):**

```ruby
public_key = OpenSSL::PKey::RSA.new(File.read("public.pem"))
payload    = JWT.decode(token, public_key, true, algorithm: "RS256").first
```

---

## API reference

### `Auth.signup(email:, password:)`
| Outcome | Keys returned |
|---|---|
| Success | `message`, `user`, `token`, `refresh_token` (if enabled) |
| Blank email | `error: "Email is required"` |
| Short password | `error: "Password must be at least N characters"` |
| Duplicate email | `error: "Email has already been taken"` |

### `Auth.login(email:, password:, ip_address: nil, user_agent: nil)`
| Outcome | Keys returned |
|---|---|
| Success | `token`, `user`, `refresh_token` (if enabled) |
| Bad credentials | `error: "Invalid email or password"` |
| Account locked | `error: "Account locked. Try again in N minute(s)."` |

### `Auth.refresh(refresh_token:)`
| Outcome | Keys returned |
|---|---|
| Success | `token`, `refresh_token`, `user` |
| Expired | `error: "Refresh token has expired"` |
| Revoked | `error: "Refresh token has been revoked"` |
| Not found | `error: "Invalid refresh token"` |

### `Auth.revoke(token:)`
| Outcome | Keys returned |
|---|---|
| Success | `message: "Token revoked successfully"` |
| Already expired | `error: "Cannot revoke an already-expired token"` |
| Invalid | `error: "Invalid token"` |

### `Auth.request_password_reset(email:)`
| Outcome | Keys returned |
|---|---|
| Known email | `message`, `reset_token` |
| Unknown email | `message` (same text — no enumeration) |

### `Auth.reset_password(reset_token:, new_password:)`
| Outcome | Keys returned |
|---|---|
| Success | `message: "Password has been reset successfully"` |
| Invalid/expired/used | `error: "Invalid or expired reset token"` |
| Short password | `error: "Password must be at least N characters"` |

### `Auth.send_magic_link(email:)`
| Outcome | Keys returned |
|---|---|
| Known email | `message`, `magic_token` |
| Unknown email | `message` (same text — no enumeration) |
| Blank email | `error: "Email is required"` |
| Feature disabled | `error: "Magic link login is not enabled"` |

### `Auth.verify_magic_link(token:)`
| Outcome | Keys returned |
|---|---|
| Success | `token`, `user`, `refresh_token` (if enabled) |
| Invalid/expired/used | `error: "Invalid or expired magic link"` |
| Blank token | `error: "Magic link token is required"` |
| Feature disabled | `error: "Magic link login is not enabled"` |

### `Auth.active_sessions(user_id:)`
| Outcome | Keys returned |
|---|---|
| Success | `sessions` (Array of `AuthSession`) |
| Feature disabled | `error: "Session tracking is not enabled"` |

### `Auth.revoke_session(jti:)`
| Outcome | Keys returned |
|---|---|
| Success | `message: "Session revoked successfully"` |
| Not found | `error: "Session not found"` |
| Blank jti | `error: "JTI is required"` |
| Feature disabled | `error: "Session tracking is not enabled"` |

### `Auth.revoke_all_sessions(user_id:)`
| Outcome | Keys returned |
|---|---|
| Success | `message: "N session(s) revoked"` |
| Feature disabled | `error: "Session tracking is not enabled"` |

### `Auth.decode(token)`
Returns the JWT payload hash on success, `nil` if invalid, expired, or revoked.

---

## JWT payload

| Claim | Value |
|---|---|
| `sub` | User primary key |
| `iat` | Issued-at Unix timestamp |
| `exp` | Expiry (`iat + token_expiry`) |
| `jti` | Unique UUID per token |

Default algorithm: **HS256** — switch to **RS256** via `config.algorithm`.

---

## Maintenance

### Prune expired revoked tokens (run from a cron job)
```ruby
ApiAuthenticationGem::RevokedToken.cleanup!
```

---

## Error classes

| Class | When raised |
|---|---|
| `ApiAuthenticationGem::ConfigurationError` | Invalid `configure` block |
| `ApiAuthenticationGem::AuthenticationError` | Reserved for future use |

---

## Running the test suite

```bash
bundle install
bundle exec rspec --format documentation
# 186 examples, 0 failures
```

Uses an in-memory SQLite database. No external services required.

---

## License

MIT — see [LICENSE.txt](LICENSE.txt).
