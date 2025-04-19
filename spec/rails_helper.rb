ENV["RAILS_ENV"] ||= "test"
require File.expand_path("../spec_helper", __FILE__)

require "active_record"
require "bcrypt"

# Simulate a minimal user model
class User < ActiveRecord::Base
  has_secure_password
end

# In-memory DB for quick tests
ActiveRecord::Base.establish_connection(adapter: "sqlite3", database: ":memory:")
ActiveRecord::Schema.define do
  create_table :users, force: true do |t|
    t.string :email
    t.string :password_digest
    t.timestamps
  end
end

RSpec.configure do |config|
  config.before(:each) { User.delete_all }
end
