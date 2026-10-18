ENV["RAILS_ENV"] ||= "test"
require File.expand_path("../spec_helper", __FILE__)

require "active_record"
require "bcrypt"

class User < ActiveRecord::Base
  has_secure_password
  validates :email, presence: true, uniqueness: true
end

ActiveRecord::Base.establish_connection(adapter: "sqlite3", database: ":memory:")

ActiveRecord::Schema.define do
  create_table :users, force: true do |t|
    t.string :email,           null: false
    t.string :password_digest, null: false
    t.string :role,            default: "user"
    t.timestamps
  end
  add_index :users, :email, unique: true

  # ---- Tier 1 ----
  create_table :api_auth_refresh_tokens, force: true do |t|
    t.integer  :user_id,    null: false
    t.string   :token,      null: false
    t.datetime :expires_at, null: false
    t.datetime :revoked_at
    t.timestamps
  end
  add_index :api_auth_refresh_tokens, :token,   unique: true
  add_index :api_auth_refresh_tokens, :user_id

  create_table :api_auth_revoked_tokens, force: true do |t|
    t.string   :jti,        null: false
    t.datetime :expires_at, null: false
    t.timestamps
  end
  add_index :api_auth_revoked_tokens, :jti, unique: true

  create_table :api_auth_password_resets, force: true do |t|
    t.string   :identifier, null: false
    t.string   :token,      null: false
    t.datetime :expires_at, null: false
    t.datetime :used_at
    t.timestamps
  end
  add_index :api_auth_password_resets, :token,      unique: true
  add_index :api_auth_password_resets, :identifier

  create_table :api_auth_lockouts, force: true do |t|
    t.string   :identifier,      null: false
    t.integer  :failed_attempts, default: 0, null: false
    t.datetime :locked_until
    t.timestamps
  end
  add_index :api_auth_lockouts, :identifier, unique: true

  # ---- Tier 2 ----
  create_table :api_auth_magic_links, force: true do |t|
    t.string   :identifier, null: false
    t.string   :token,      null: false
    t.datetime :expires_at, null: false
    t.datetime :used_at
    t.timestamps
  end
  add_index :api_auth_magic_links, :token,      unique: true
  add_index :api_auth_magic_links, :identifier

  create_table :api_auth_sessions, force: true do |t|
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

RSpec.configure do |config|
  config.before(:each) do
    User.delete_all
    ApiAuthenticationGem::RefreshToken.delete_all
    ApiAuthenticationGem::RevokedToken.delete_all
    ApiAuthenticationGem::PasswordReset.delete_all
    ApiAuthenticationGem::Lockout.delete_all
    ApiAuthenticationGem::MagicLink.delete_all
    ApiAuthenticationGem::AuthSession.delete_all
  end
end
