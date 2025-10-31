#!/bin/bash

# Generate more realistic SELinux test scenarios

# Create a custom policy module (optional)
mkdir -p /root/selinux-test

cat > /root/selinux-test/myapp.te << 'EOF'
policy_module(myapp, 1.0.0)

require {
    type httpd_t;
    type user_home_t;
    class file { read open };
}

# Allow httpd to read user home files (for testing)
# allow httpd_t user_home_t:file { read open };
EOF

# Compile and install the policy (commented out by default)
# cd /root/selinux-test
# checkmodule -M -m -o myapp.mod myapp.te
# semodule_package -o myapp.pp -m myapp.mod
# semodule -i myapp.pp

# Create various file contexts for testing
echo "Creating diverse SELinux test scenarios..."

# Web server related
mkdir -p /srv/webapp
echo "Custom webapp content" > /srv/webapp/app.html
semanage fcontext -a -t httpd_sys_content_t "/srv/webapp(/.*)?"
restorecon -Rv /srv/webapp

# Log files
mkdir -p /var/log/myapp
touch /var/log/myapp/application.log
chown testuser:testuser /var/log/myapp/application.log
semanage fcontext -a -t var_log_t "/var/log/myapp(/.*)?"
restorecon -Rv /var/log/myapp

# User executables
mkdir -p /home/testuser/bin
cat > /home/testuser/bin/myapp.sh << 'SCRIPT'
#!/bin/bash
echo "My application running"
logger "MyApp executed"
SCRIPT
chmod +x /home/testuser/bin/myapp.sh
chown -R testuser:testuser /home/testuser/bin

echo "SELinux test environment configured!"