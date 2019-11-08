require 'securerandom'
require 'base64'

Puppet::Type.newtype(:mongos_user) do
  @doc = 'Manage a Mongos user. This includes management of users password as well as privileges.'

  ensurable

  def initialize(*args)
    super
    # Sort roles array before comparison.
    self[:roles] = Array(self[:roles]).sort!
  end

  newparam(:name, :namevar=>true) do
    desc "The name of the resource."
  end

  newproperty(:username) do
    desc "The name of the user."
    defaultto { @resource[:name] }
  end

  newproperty(:database) do
    desc "The user's target database."
    defaultto do
      fail("Parameter 'database' must be set") if provider.database == :absent
    end
    newvalues(/^[\w-]+$/)
  end

  newparam(:tries) do
    desc "The maximum amount of two second tries to wait MongoDB startup."
    defaultto 10
    newvalues(/^\d+$/)
    munge do |value|
      Integer(value)
    end
  end

  newproperty(:roles, :array_matching => :all) do
    desc "The user's roles."
    defaultto ['dbAdmin']
    newvalue(/^\w+(|@[\w-]+)$/)

    # Pretty output for arrays.
    def should_to_s(value)
      value.inspect
    end

    def is_to_s(value)
      value.inspect
    end
  end

  newproperty(:password_hash) do
    desc "The password hash of the user. Use mongodb_password() for creating hash."
    defaultto do
      fail("Property 'password_hash' must be set. Use mongodb_password() for creating hash.") if provider.database == :absent
    end

    def insync?(is)
      digest = OpenSSL::Digest::SHA1.new.freeze

      # SaltedPassword  := Hi(Normalize(password), salt, i)
      salted_password = OpenSSL::PKCS5.pbkdf2_hmac_sha1(
        should,
        Base64.strict_decode64(is['salt']),
        is['iterationCount'],
        digest.size
      )

      # ClientKey       := HMAC(SaltedPassword, "Client Key")
      client_key = OpenSSL::HMAC.digest(digest, salted_password, "Client Key")

      # StoredKey       := H(ClientKey)
      stored_key = digest.digest(client_key)

      return Base64.strict_encode64(stored_key) == is['storedKey']
    end
    newvalue(/^\w+$/)
  end

  autorequire(:package) do
    'mongodb_client'
  end

  autorequire(:service) do
    'mongodb'
  end
end
