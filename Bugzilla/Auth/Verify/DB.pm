# -*- Mode: perl; indent-tabs-mode: nil -*-
#
# The contents of this file are subject to the Mozilla Public
# License Version 1.1 (the "License"); you may not use this file
# except in compliance with the License. You may obtain a copy of
# the License at http://www.mozilla.org/MPL/
#
# Software distributed under the License is distributed on an "AS
# IS" basis, WITHOUT WARRANTY OF ANY KIND, either express or
# implied. See the License for the specific language governing
# rights and limitations under the License.
#
# The Original Code is the Bugzilla Bug Tracking System.
#
# The Initial Developer of the Original Code is Netscape Communications
# Corporation. Portions created by Netscape are
# Copyright (C) 1998 Netscape Communications Corporation. All
# Rights Reserved.
#
# Contributor(s): Terry Weissman <terry@mozilla.org>
#                 Dan Mosedale <dmose@mozilla.org>
#                 Joe Robins <jmrobins@tgix.com>
#                 Dave Miller <justdave@syndicomm.com>
#                 Christopher Aillon <christopher@aillon.com>
#                 Gervase Markham <gerv@gerv.net>
#                 Christian Reis <kiko@async.com.br>
#                 Bradley Baetz <bbaetz@acm.org>
#                 Erik Stambaugh <erik@dasbistro.com>

package Bugzilla::Auth::Verify::DB;
#use strict;
use warnings;
use base qw(Bugzilla::Auth::Verify);

use Bugzilla::Constants;
use Bugzilla::Token;
use Bugzilla::Util;
use Bugzilla::User;
use Digest::MD5 qw[md5_hex md5];
use MIME::Base64;
use List::Util qw[min];

my $itoa64 = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';

sub _get_random_number {
    my $myrand = 0;
    my $low_n = 100000;
    my $high_n = 999999;

    while ($myrand < $low_n || $myrand > $high_n) {
        $myrand = $low_n + int( rand($high_n - $low_n + 1) );
    }

    return $myrand;
}

sub _get_password_hash {
    my $password = shift;

    my $myrandom = _get_random_number;

    my $myhash = _hash_crypt_private($password, _hash_gensalt_private($myrandom));

    return $myhash  if length($myhash) == 34;

    my $m = md5_hex $myhash;
}

sub _hash_gensalt_private {
    my $myinput = shift;
    my $iteration_count_log2 = shift || 6;

    $iteration_count_log2 = 8 if $iteration_count_log2 < 4 || $iteration_count_log2 > 31;

    my $myoutput = '$H$';
    $myoutput .= substr($itoa64, min($iteration_count_log2 + 5, 30), 1);
    $myoutput .= _hash_encode64($myinput, 6);

    return $myoutput;
}

sub _hash_crypt_private {
    my ($password, $setting) = @_;

    my $myoutput = '*';

    # Check for correct hash
    return $myoutput unless $setting =~ m/^\$H\$/;

    # Note: could be a subtle difference in behaviour on the next line
    my $count_log2 = index($itoa64, substr($setting, 3, 1));
    if ($count_log2 == -1) {
        $count_log2 = 0;
    }

    if (($count_log2 < 7) || ($count_log2 > 30)) {
        return $myoutput;
    }

    my $count = 1 << $count_log2;
    my $salt = substr($setting, 4, 8);

    if (length($salt) != 8) {
        return $myoutput;
    }

    my $myhash = md5($salt . $password);
    $myhash = md5($myhash . $password) while ($count--);

    $myoutput = substr $setting, 0, 12;
    $myoutput .= _hash_encode64($myhash, 16);

    return $myoutput;

}

sub _hash_encode64 {
    my $myinput = shift;
    my $count = shift;

    my $myoutput = '';
    my $i = 0;
    while ($i < $count) {

        my $value = ord(substr($myinput, $i, 1));

        $i += 1;
        $myoutput .= substr($itoa64, $value & 0x3f, 1);
        if ($i < $count) {
            $value |= ord(substr($myinput, $i, 1)) << 8;
        }
        $myoutput .= substr($itoa64, ($value >> 6) & 0x3f, 1);
        if ($i >= $count) {
            last;
        }
        $i += 1;

        if ($i < $count) {
            $value |= ord(substr($myinput, $i, 1)) << 16;
        }

        $myoutput .= substr($itoa64, ($value >> 12) & 0x3f, 1);
        if ($i >= $count) {
            last;
        }
        $i += 1;

        $myoutput .= substr($itoa64, ($value >> 18) & 0x3f, 1);

    }

    return $myoutput;
}
sub phpbb3_check_credentials {

    my $password = shift;
    my $myhash = shift;

    #open (FOO, '>>/home/sabayonlinux/public_html/bugs.sabayonlinux.org/fook.txt');
    #my $foo = _hash_crypt_private($password, $myhash);
    #print FOO "_hash_crypt_private: $foo ($password | $myhash)\n";
    #close(FOO);

    if (_hash_crypt_private($password, $myhash) eq $myhash) {
        return 1;
    }
    return 0;

}

sub check_credentials {
    my ($self, $login_data) = @_;
    my $dbh = Bugzilla->dbh;

    my $username = $login_data->{username};
    my $password = $login_data->{password};
    my $user_id  = login_to_id($username);
    my $user_phpbb_login_ok = 0;
    my $phpbb3_password_encrypted = '';
    my $phpbb3_username = '';
    my $phpbb3_email = '';

    trick_taint($username);
    trick_taint($password);

    # if username is an email, look for email, otherwise look for username
    if (validate_email_syntax($username)) {

        ($phpbb3_password_encrypted, $phpbb3_username) = $dbh->selectrow_array(
            "SELECT phpbb3.phpbb_users.user_password,phpbb3.phpbb_users.username " .
            "FROM phpbb3.phpbb_users WHERE phpbb3.phpbb_users.user_email = ?",
            undef, $username );
        $phpbb3_email = $username;

    } else {

        ($phpbb3_password_encrypted, $phpbb3_email) = $dbh->selectrow_array(
            "SELECT phpbb3.phpbb_users.user_password,phpbb3.phpbb_users.user_email " .
            "FROM phpbb3.phpbb_users WHERE phpbb3.phpbb_users.username = ?",
            undef, $username );
        $phpbb3_username = $username;
        $username = $phpbb3_email;
        if ($username) {
            $user_id  = login_to_id($username);
        }

    }

    if ($phpbb3_password_encrypted) {
        # user email is found, we need to verify it against the provided
        # password
        my $phpbb3_valid = phpbb3_check_credentials($password, $phpbb3_password_encrypted);
        #open (FOO, '>>/home/sabayonlinux/public_html/bugs.sabayonlinux.org/fook.txt');
        #print FOO "valid: $phpbb3_valid | password: $password | encrypted: $phpbb3_password_encrypted | username: $username | user id: $user_id\n";
        #close(FOO);

        if (($phpbb3_valid) && (!$user_id)) {
            # create bugzilla user since it doesn't seem to exist
            $user_id = Bugzilla::User->create({
                login_name => $username,
                realname   => $phpbb3_username,
                cryptpassword => $password});
            $user_phpbb_login_ok = 1;
        } elsif (($phpbb3_valid) && ($user_id)) {
            $user_phpbb_login_ok = 1;
        }

    }

    return { failure => AUTH_NO_SUCH_USER } unless $user_id;

    $login_data->{bz_username} = $username;

    my ($real_password_crypted) = $dbh->selectrow_array(
        "SELECT cryptpassword FROM profiles WHERE userid = ?",
        undef, $user_id);

    # Using the internal crypted password as the salt,
    # crypt the password the user entered.
    my $entered_password_crypted = bz_crypt($password, $real_password_crypted);
 
    return { failure => AUTH_LOGINFAILED }
        if (($entered_password_crypted ne $real_password_crypted) && ($user_phpbb_login_ok == 0));

    # Force the user to type a longer password if it's too short.
    if (length($password) < USER_PASSWORD_MIN_LENGTH) {
        return { failure => AUTH_ERROR, user_error => 'password_current_too_short',
                 details => { locked_user => $user } };
    }

    # The user's credentials are okay, so delete any outstanding
    # password tokens they may have generated.
    Bugzilla::Token::DeletePasswordTokens($user_id, "user_logged_in");

    # If their old password was using crypt() or some different hash
    # than we're using now, convert the stored password to using
    # whatever hashing system we're using now.
    my $current_algorithm = PASSWORD_DIGEST_ALGORITHM;
    if ($real_password_crypted !~ /{\Q$current_algorithm\E}$/) {
        my $new_crypted = bz_crypt($password);
        $dbh->do('UPDATE profiles SET cryptpassword = ? WHERE userid = ?',
                 undef, $new_crypted, $user_id);
    }

    return $login_data;
}

sub change_password {
    my ($self, $user, $password) = @_;
    my $dbh = Bugzilla->dbh;
    my $cryptpassword = bz_crypt($password);
    $dbh->do("UPDATE profiles SET cryptpassword = ? WHERE userid = ?",
             undef, $cryptpassword, $user->id);
}

1;
