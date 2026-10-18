# Fixed owned-fixture inventory. Concatenated with one reviewed main program.
use strict;
use warnings;
use Digest::SHA qw(sha256_hex);
use JSON::PP;
use Fcntl qw(O_RDONLY O_NONBLOCK O_WRONLY O_CREAT O_EXCL O_NOFOLLOW S_ISDIR S_ISREG);
use Errno qw(ENOENT);

my $PREFIX = '/System/Volumes/Data/Library/GlueMVPFixtures';
my $ARCHIVE = '/System/Volumes/Data/Library/GlueMVPFixtures-retained-1b85f0ac-da1aaf9a';
my $ATTEMPT = '/System/Volumes/Data/private/tmp/glue-kit03-retain-attempt-da1aaf9a396020b3';
my $BUILD = '1b85f0ac3d3ec2de7df50004ee2732d8d5c049adb44193383245050f800fa11d';
my $TMP = '/System/Volumes/Data/private/tmp/';
my @ROOTS = ($PREFIX, '/System/Volumes/Data/Library/GlueMVPFixtures-retained-a75d54bb-1ee4bbe2');
for my $nonce (qw(c10ed2e4ce0404bd 6ae386cc044ff2a1 1ee4bbe2b443c268 da1aaf9a396020b3)) {
    push @ROOTS, map { $TMP . $_ . $nonce } qw(glue-bs-stage- glue-bs-user- glue-bs-launch-);
    push @ROOTS, map { $TMP . 'glue-bs-' . $nonce . '-' . $_ } qw(positive simulated denied trailing);
}
push @ROOTS, map { $TMP . $_ . '1ee4bbe2b443c268-03' } qw(glue-bs-retain-stage- glue-bs-retain-launch-);
my @PARENTS = ('/', '/System', '/System/Volumes', '/System/Volumes/Data',
    '/System/Volumes/Data/Library', '/System/Volumes/Data/private', $TMP =~ s{/$}{}r);
my %ARTIFACTS = (
    'bootstrap-runner' => [110768, '2e3714e8d6503a21a76947ad93f3328419dcf0b2bf21909145d819e437ffcceb'],
    'context-probe' => [52912, 'b15f974ed14129d738b8963d8d8d865502e73e9be11436105468e071ee8cbf67'],
    'make-request' => [72240, '28dea7f9bc8aaabb0ce1421e55522b8cf4a9f7efa6e3b79aa8a4ae6f92c164b8'],
);
my $JSON = JSON::PP->new->canonical->ascii;
my ($entry_count, $byte_count, $entry_device);
sub fail { die "kit03 inventory: $_[0]\n"; }
sub canonical { return $JSON->encode($_[0]); }
sub report {
    my $bytes = canonical($_[0]) . "\n";
    fail('report bound') if length($bytes) > 1048576;
    print $bytes or fail('report write');
}
sub status_of {
    my ($path) = @_;
    my @s = lstat($path);
    return \@s if @s;
    return undef if $! == ENOENT;
    fail("lstat failed: $path: $!");
}
# Perl stat timestamps have seconds resolution. These checks require the
# coordinated stable namespace; they do not exclude adversarial rapid writes.
sub unchanged {
    my ($before, $after, $path) = @_;
    fail("entry changed: $path") unless $after && join(':', @$before[0..7,9..12]) eq join(':', @$after[0..7,9..12]);
}
sub no_acl {
    my ($path) = @_;
    open(my $pipe, '-|', '/bin/ls', '-lde', $path) or fail("ACL command: $path");
    my $line = <$pipe>;
    my $extra = <$pipe>;
    close($pipe) or fail("ACL command status: $path");
    fail("ACL or malformed permissions: $path") unless defined($line) && !defined($extra) &&
        $line =~ /\A([d-][rwxStTs-]{9})[\@ ] / && $1 !~ /\+/;
}
sub metadata {
    my ($s) = @_;
    return {device => 0+$s->[0], inode => 0+$s->[1], mode => 0+$s->[2],
        links => 0+$s->[3], uid => 0+$s->[4], gid => 0+$s->[5], size => 0+$s->[7]};
}
sub entry {
    my ($path, $relative, $depth, $entries) = @_;
    fail('tree bound') if ++$entry_count > 2048 || $depth > 5;
    my $s = status_of($path) // fail("entry disappeared: $path");
    fail("mount boundary: $path") unless $s->[0] == $entry_device;
    fail("unapproved owner: $path") unless ($s->[4] == 0 || $s->[4] == 501) &&
        ($s->[5] == 0 || $s->[5] == 20);
    no_acl($path);
    my $m = metadata($s);
    $m->{relative} = $relative;
    if (S_ISDIR($s->[2])) {
        fail("writable directory: $path") if $s->[2] & 0022;
        opendir(my $dir, $path) or fail("opendir: $path: $!");
        my @fd = stat($dir);
        fail("directory handle differs: $path") unless @fd && $fd[0] == $s->[0] && $fd[1] == $s->[1];
        my @names;
        while (defined(my $name = readdir($dir))) {
            next if $name eq '.' || $name eq '..';
            fail("entry name or roster bound: $path") unless $name =~ /\A[A-Za-z0-9._-]{1,128}\z/ && @names < 128;
            push @names, $name;
        }
        closedir($dir) or fail("closedir: $path");
        $m->{names} = [sort @names];
        push @$entries, $m;
        for my $name (sort @names) {
            entry("$path/$name", $relative eq '.' ? $name : "$relative/$name", $depth+1, $entries);
        }
    } elsif (S_ISREG($s->[2])) {
        fail("file mode/link/size: $path") if $s->[3] != 1 || ($s->[2] & 0022) ||
            $s->[7] < 0 || $s->[7] > 4194304;
        $byte_count += $s->[7];
        fail('total byte bound') if $byte_count > 67108864;
        sysopen(my $file, $path, O_RDONLY|O_NOFOLLOW|O_NONBLOCK) or fail("open: $path: $!");
        binmode($file);
        my @fd = stat($file);
        unchanged($s, \@fd, $path);
        my $digest = Digest::SHA->new(256);
        my $read = 0;
        while (1) {
            my $n = sysread($file, my $bytes, 65536);
            fail("read: $path: $!") unless defined($n);
            last unless $n;
            $read += $n;
            fail("file grew: $path") if $read > $s->[7];
            $digest->add($bytes);
        }
        fail("short file: $path") unless $read == $s->[7];
        my @end = stat($file);
        unchanged($s, \@end, $path);
        close($file) or fail("close: $path");
        $m->{sha256} = $digest->hexdigest;
        push @$entries, $m;
    } else { fail("symlink or special file: $path"); }
    unchanged($s, status_of($path), $path);
}
sub snapshot {
    my ($relocated, $data_device) = @_;
    ($entry_count, $byte_count, $entry_device) = (0, 0, $data_device);
    my (%parents, %roots);
    for my $path (@PARENTS) {
        my $s = status_of($path) // fail("missing parent: $path");
        my $mode = $path eq ($TMP =~ s{/$}{}r) ? 041777 : 040755;
        fail("parent policy: $path") unless S_ISDIR($s->[2]) && $s->[2] == $mode && $s->[4] == 0 && $s->[5] == 0 && $s->[0] == $data_device;
        no_acl($path);
        $parents{$path} = {map { $_ => metadata($s)->{$_} } qw(device inode mode uid gid)};
    }
    for my $logical (@ROOTS) {
        my $physical = $relocated && $logical eq $PREFIX ? $ARCHIVE : $logical;
        my $s = status_of($physical);
        if (!$s) { $roots{$logical} = undef; next; }
        fail("root device/type: $physical") unless S_ISDIR($s->[2]) && $s->[0] == $data_device;
        my @entries;
        entry($physical, '.', 0, \@entries);
        $roots{$logical} = \@entries;
    }
    return {parents => \%parents, roots => \%roots};
}
sub verify_kit03 {
    my ($snapshot) = @_;
    my $entries = $snapshot->{roots}{$PREFIX} // fail('live kit03 absent');
    my %by_name = map { $_->{relative} => $_ } @$entries;
    fail('live kit03 roster') unless keys(%by_name) == 5 &&
        canonical($by_name{'.'}{names}) eq canonical([$BUILD]) &&
        canonical($by_name{$BUILD}{names}) eq canonical([sort keys %ARTIFACTS]);
    for my $relative ('.', $BUILD) {
        my $m = $by_name{$relative};
        fail('live kit03 directory policy') unless $m->{uid} == 0 && $m->{gid} == 0 && $m->{mode} == 040755;
    }
    for my $name (sort keys %ARTIFACTS) {
        my $m = $by_name{"$BUILD/$name"} // fail('missing payload');
        fail('live kit03 payload differs') unless $m->{uid} == 0 && $m->{gid} == 0 &&
            $m->{mode} == 0100555 && $m->{links} == 1 && $m->{size} == $ARTIFACTS{$name}[0] &&
            $m->{sha256} eq $ARTIFACTS{$name}[1];
    }
}
sub signatures {
    my ($relocated) = @_;
    my @receipts;
    for my $name (sort keys %ARTIFACTS) {
        my @argv = ('/usr/bin/codesign', '--verify', '--strict', '--verbose=2',
            ($relocated ? $ARCHIVE : $PREFIX) . "/$BUILD/$name");
        my $rc;
        { local *STDOUT; open(STDOUT, '>&', \*STDERR) or fail('signature stream');
          $rc = system {$argv[0]} @argv; }
        push @receipts, {argv => \@argv, raw_status => $rc, streams => 'combined-in-phase.stderr'};
        fail("signature failed: $name") unless $rc == 0;
    }
    return \@receipts;
}
