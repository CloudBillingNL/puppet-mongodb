require File.expand_path(File.join(File.dirname(__FILE__), '..', 'mongodb'))
Puppet::Type.type(:mongos_user).provide(:mongodb, :parent => Puppet::Provider::Mongodb) do

  desc "Manage users for a MongoDB cluster."

  defaultfor :kernel => 'Linux'

  def self.instances
    require 'json'

    users = JSON.parse mongo_eval('printjson(db.system.users.find().toArray())', 'admin', 10, 'localhost:27017')

    users.map do |user|
      new(name: user['_id'],
          ensure: :present,
          username: user['user'],
          database: user['db'],
          roles: from_roles(user['roles'], user['db']),
          password_hash: user['credentials']['MONGODB-CR'],
          scram_credentials: user['credentials']['SCRAM-SHA-1'])
    end
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
    password_hash = @resource[:password_hash]
    if !password_hash && @resource[:password]
      password_hash = Puppet::Util::MongodbMd5er.md5(@resource[:username], @resource[:password])
    end

    command = {
      createUser: @resource[:username],
      pwd: password_hash,
      customData: {
        createdBy: "Puppet Mongodb_user['#{@resource[:name]}']"
      },
      roles: role_hashes(@resource[:roles], @resource[:database]),
      digestPassword: false
    }

    if mongo_4?
      # SCRAM-SHA-256 requires digestPassword to be true.
      command[:mechanisms] = ['SCRAM-SHA-1']
    end

    mongo_eval("db.runCommand(#{command.to_json})", @resource[:database], 10, 'localhost:27017')
  end

  def destroy
    mongo_eval("db.dropUser(#{@resource[:username].to_json})", "admin", 10, 'localhost:27017')
  end

  def exists?
    !(@property_hash[:ensure] == :absent || @property_hash[:ensure].nil?)
  end

  def password_hash=(_value)
    command = {
      updateUser: @resource[:username],
      pwd: @resource[:password_hash],
      digestPassword: false
    }

    mongo_eval("db.runCommand(#{command.to_json})", @resource[:database], 'admin', 10, 'localhost:27017')
  end

  def password=(value)
    if mongo_26?
      mongo_eval("db.changeUserPassword(#{@resource[:username].to_json}, #{value.to_json})", @resource[:database])
    else
      command = {
        updateUser: @resource[:username],
        pwd: @resource[:password],
        digestPassword: true
      }

      mongo_eval("db.runCommand(#{command.to_json})", @resource[:database], 'admin', 10, 'localhost:27017')
    end
  end

  def roles=(roles)
    grant = to_roles(roles, @resource[:database]) - to_roles(@property_hash[:roles], @resource[:database])
    unless grant.empty?
      mongo_eval("db.getSiblingDB(#{@resource[:database].to_json}).grantRolesToUser(#{@resource[:username].to_json}, #{role_hashes(grant, @resource[:database]).to_json})", 'admin', 10, 'localhost:27017')
    end

    revoke = to_roles(@property_hash[:roles], @resource[:database]) - to_roles(roles, @resource[:database])
    unless revoke.empty?
      mongo_eval("db.getSiblingDB(#{@resource[:database].to_json}).revokeRolesFromUser(#{@resource[:username].to_json}, #{role_hashes(revoke, @resource[:database]).to_json})", 'admin', 10, 'localhost:27017')
    end
  end

  private

  def self.from_roles(roles, db)
    roles.map do |entry|
      if entry['db'].empty? || entry['db'] == db
        entry['role']
      else
        "#{entry['role']}@#{entry['db']}"
      end
    end.sort
  end

  def to_roles(roles, db)
    roles.map do |entry|
      if entry.include? '@'
        entry
      else
        "#{entry}@#{db}"
      end
    end
  end

  def role_hashes(roles, db)
    roles.sort.map do |entry|
      if entry.include? '@'
        {
          'role' => entry.gsub(%r{^(.*)@.*$}, '\1'),
          'db'   => entry.gsub(%r{^.*@(.*)$}, '\1')
        }
      else
        {
          'role' => entry,
          'db'   => db
        }
      end
    end
  end
end
