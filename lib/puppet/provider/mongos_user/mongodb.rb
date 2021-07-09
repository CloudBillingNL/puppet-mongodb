require File.expand_path(File.join(File.dirname(__FILE__), '..', 'mongodb'))
Puppet::Type.type(:mongos_user).provide(:mongodb, :parent => Puppet::Provider::Mongodb) do

  desc "Manage users for a Mongos database."

  defaultfor :kernel => 'Linux'

  def self.instances
    require 'json'
    dbs = JSON.parse mongo_eval('printjson(db.getMongo().getDBs()["databases"].map(function(db){return db["name"]}))', 'admin', 10, 'localhost:27017') || 'admin'

    allusers = []

    dbs.each do |db|
      users = JSON.parse mongo_eval('printjson(db.system.users.find().toArray())', db, 10, 'localhost:27017')

      allusers += users.collect do |user|
        new(name: user['_id'],
            ensure: :present,
            username: user['user'],
            database: db,
            roles: from_roles(user['roles'], user['db']),
            password_hash: user['credentials']['MONGODB-CR'],
            scram_credentials: user['credentials']['SCRAM-SHA-1'])
      end
    end

    return allusers
  end

  # Assign prefetched users based on username and database, not on id and name
  def self.prefetch(resources)
    users = instances
    resources.each do |name, resource|
      if provider = users.find { |user| user.username == resource[:username] and user.database == resource[:database] }
        resources[name].provider = provider
      end
    end
  end

  mk_resource_methods

  def create
    user = {
      :user => @resource[:username],
      :pwd => @resource[:password_hash],
      :roles => to_roles(@resource[:roles])
    }

    mongo_eval("db.addUser(#{user.to_json})", @resource[:database], 10, 'localhost:27017')

    @property_hash[:ensure] = :present
    @property_hash[:username] = @resource[:username]
    @property_hash[:database] = @resource[:database]
    @property_hash[:password_hash] = ''
    @property_hash[:roles] = @resource[:roles]

    exists? ? (return true) : (return false)
  end


  def destroy
    if mongo_24?
      mongo_eval("db.removeUser('#{@resource[:username]}')", 'admin', 10, 'localhost:27017')
    else
      mongo_eval("db.dropUser('#{@resource[:username]}')", 'admin', 10, 'localhost:27017')
    end
  end

  def exists?
    !(@property_hash[:ensure] == :absent or @property_hash[:ensure].nil?)
  end

  def password_hash=(value)
    cmd_json=<<-EOS.gsub(/^\s*/, '').gsub(/$\n/, '')
    {
        "updateUser": "#{@resource[:username]}",
        "pwd": "#{@resource[:password_hash]}",
        "digestPassword": false
    }
    EOS
    mongo_eval("db.runCommand(#{cmd_json})", @resource[:database], 10, 'localhost:27017')
  end

  def roles=(roles)
    if mongo_24?
      mongo_eval("db.system.users.update({user:'#{@resource[:username]}'}, { $set: {roles: #{to_roles(@resource[:roles]).to_json}}})", 'admin', 10, 'localhost:27017')
    else
      grant = roles-@property_hash[:roles]
      if grant.length > 0
        mongo_eval("db.getSiblingDB('#{@resource[:database]}').grantRolesToUser('#{@resource[:username]}', #{to_roles(grant).to_json})", 'admin', 10, 'localhost:27017')
      end

      revoke = @property_hash[:roles]-roles
      if revoke.length > 0
        mongo_eval("db.getSiblingDB('#{@resource[:database]}').revokeRolesFromUser('#{@resource[:username]}', #{to_roles(revoke).to_json})", 'admin', 10, 'localhost:27017')
      end
    end
  end

  private

  def self.from_roles(roles, db)
    roles.map do |entry|
      if entry['db'] == db
        entry['role']
      else
        "#{entry['role']}@#{entry['db']}"
      end
    end.sort
  end

  def to_roles(roles)
    roles.map do |role|
      parts = role.split('@')
      if parts.count < 2
        role
      else
        { "role" => parts[0], "db" => parts[1] }
      end
    end
  end
end
