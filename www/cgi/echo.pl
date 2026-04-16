#!/usr/bin/perl

# CGI script that dumps Apache environment variables for debugging.
# Sensitive variables (secrets, passwords, tokens) are redacted.
# This endpoint is only served behind OIDC authentication (toc vhost).
# Remove or disable this file in production if you do not need it.

my @REDACT = qw(
    OIDC_CLIENT_SECRET
    REDIS_PASSWORD
    OIDC_CRYPTO_PASSPHRASE
    HTTP_AUTHORIZATION
    HTTP_COOKIE
);
my %redact_set = map { $_ => 1 } @REDACT;

print "Content-type: text/html\n\n";
print "<pre>\n";

foreach my $key (sort keys %ENV) {
    my $val = $redact_set{$key} ? '*** REDACTED ***' : $ENV{$key};
    printf "%s = %s\n", $key, $val;
}
print "</pre>\n";
