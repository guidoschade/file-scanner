#!/usr/bin/env perl

use strict;
use warnings;
use File::Find;
use Fcntl ':mode';

my ($num, @dirs, @excludes, %uidtab, %gidtab);

if (scalar(@ARGV) ne 4)
{
 print "$0 is a tool used to compare two directories\n";
 print "usage: $0 -d <directory>[:<directory] -x <exclude>[:<exclude>]\n";
 exit 0;
}

@dirs = split ":", $ARGV[1];
@excludes = split ":", $ARGV[3];

#scanPkgs(); # only works for Solaris
#scanContents(); # only works for Solaris

# scan all given dirs
foreach $num (0..$#dirs) { scanDir($dirs[$num]); }
exit 0;

##############################################
# file find routine
##############################################
sub getInfo
{
  my $fname = $_;
  my ($dev,$ino,$mode,$nlink,$uid,$gid,$rdev,$size) = lstat($fname); 
  if (!$ino) { print "FIL|0|0|0|0|0|$fname|-stat failed-||\n"; return; }

  my $perm = $mode & 07777;
  my $type = ($mode & 770000) >> 12;
  my $target = "";
  my $sum = "0";
  my ($user, $group);

  {
    if (S_ISREG($mode)) { $type = "f"; next; }
    if (S_ISDIR($mode)) { $type = "d"; next; }
    if (S_ISBLK($mode)) { $type = "b"; next; }
    if (S_ISCHR($mode)) { $type = "c"; next; }
    if (S_ISFIFO($mode)) { $type = "p"; next; }
    if (S_ISSOCK($mode)) { $type = "s"; next; }
    if (S_ISLNK($mode)) { $type = "l"; next; }
  }

  # we don't need the size of a directory
  if ($type eq "d") { $size = "0"; }

  if ($type eq "l") # check for symbolic link
  {
    $target = readlink($fname);
    if (! -e $fname) { $perm = "0"; } # check if link is broken
  }
  elsif ($type eq "f") # regular file
  {
    # do not calculate checksum for logfiles or files with size > 20MB
    if (($fname !~ /.*\.log$/) && $size < 20000000) { $sum = &calcCheckSum($fname); }
  }

  # get username and groupname (and cache them)
  if (defined $uidtab{$uid}) { $user = $uidtab{$uid}; } else { $user = getpwuid($uid); $uidtab{$uid} = $user; }
  if (defined $gidtab{$gid}) { $group = $gidtab{$gid}; } else { $group = getgrgid($gid); $gidtab{$gid} = $group; }

  if (!defined $user) { $user = $uid; };
  if (!defined $group) { $group = $gid; };

  printf "FIL|%s|%04o|%s|%s|%d|%s|%s|%s|\n", $type, $perm, $user, $group, $size, $fname, $sum, $target;
}

##############################################
# avoid scanning certain directories
##############################################
sub preProcess
{
  my (@list) = @_;
  my ($num, $num2);
  my $path;
  my $count = 0;

  foreach $num (0..$#list)
  {
    $path = $File::Find::dir."/".$list[$num];
    if ($path =~ m|/\.snapshot/|) { $list[$num]="."; $count ++; next; };
    if ($path =~ m|/lost+found/|) { $list[$num]="."; $count ++; next; };

    foreach $num2 (0..$#excludes) # skip unwanted directories
    {
      if ($path =~ m|^$excludes[$num2]|) { $list[$num]="."; $count ++; next; }
    }
  }

  @list = sort(@list);
  @list = splice(@list, 2+$count);
  #foreach $num (0..$#list) { print "l: $list[$num]\n"; }
  return @list;
}

##############################################
# scan single mountpoint
##############################################
sub scanDir
{
  my $dir = shift;
  find({wanted => \&getInfo, preprocess => \&preProcess, no_chdir => 1 }, $dir);
}

###############################################################
# Calculate Checksum
###############################################################
sub calcCheckSum
{
  my $file = shift;
  my ($sum, $buffer);

  open(FILE, $file) or return("-read error-");
  binmode(FILE);
  $sum = sysvsum(\*FILE);
  close(FILE);
  return($sum);
}

##############################################################
# calc system 5 sum (/usr/bin/sum - solaris)
##############################################################
sub sysvsum
{
  my($fh) = shift;
  my($crc) = my($len) = 0;
  my($buf,$num,$i);
  my($buflen) = 16384;

  while($num = sysread $fh, $buf, $buflen)
  {
    $len += $num;
    $crc += unpack("%32C*", $buf);
  }

  $crc = ($crc & 0xffff) + ($crc & 0xffffffff) / 0x10000;
  $crc = ($crc & 0xffff) + ($crc / 0x10000);
  return int($crc);
}

##############################################
# package find routine
##############################################
sub scanPkgs
{
  my $c = "/usr/bin/egrep '^VERSION' /var/sadm/pkg/*/pkginfo";
  my ($lin, @ar, @ar2);

  open(CMD, "$c |") or die "Cannot open command $c\n";
  while(<CMD>)
  {
    $lin = $_;
    chomp($lin);
    @ar = split "/", $lin;
    @ar2 = split ":", $ar[5];
    $ar2[1] =~ s|^VERSION=(.*)$|$1|g;
    $ar[4] =~ s|^(.*)\.\d$|$1|g;
    print "PKG|$ar[4]|$ar2[1]\n";
  }
  close CMD;
}

##############################################
# contents routine
##############################################
sub scanContents
{
  my ($num, $num2, $sum, $name, $line, $target, $owner);
  my ($pkgs, $group, $size, $type, $perms);
  my @ar;

  open(FIL, "/var/sadm/install/contents") or die "Cannot open contents file\n";
  A: while(<FIL>)
  {
    $line = $_;

    # only include certain lines
    foreach $num (0..$#dirs) 
    {
      if ($line =~ m|^$dirs[$num]|) 
      {
        foreach $num2 (0..$#excludes) # skip unwanted directories
        {
          if ($line =~ m|^$excludes[$num2]|) { next A; }
        }

        @ar = split " ", $line;

        # special file
        if ($ar[1] eq "c" || $ar[1] eq "b")
        {
	  $name  = $ar[0];
          $type = $ar[1];
          $target = "";
          $perms = $ar[5];
          $owner = $ar[6];
          $group = $ar[7];
          $size  = "0";
          $sum = "0";
          $pkgs  = join (" ", (splice @ar, 8, $#ar - 7));
        }

        # directory
        if ($ar[1] eq "d" || $ar[1] eq "x")
        {
          $name  = $ar[0];
          $type = "d";
          $target = "";
          $perms = $ar[3];
          $owner = $ar[4];
          $group = $ar[5];
          $size  = "0";
          $sum = "0";
          $pkgs  = join (" ", (splice @ar, 6, $#ar - 5));
        }

	# plain file
        if ($ar[1] eq "f" || $ar[1] eq "e" || $ar[1] eq "v")
        {
          $name  = $ar[0];
          $type = "f";
          $target = "";
          $perms = $ar[3];
          $owner = $ar[4];
          $group = $ar[5];
          $size  = $ar[6];
          $sum   = $ar[7];
          $pkgs  = join (" ", (splice @ar, 9, $#ar - 8));
        }

        # link (symbolic)
        if ($ar[1] eq "s" || $ar[1] eq "l")
        {
          $type = "l";
          my @s = split "=", $ar[0];
          $target = $s[1];
          $name  = $s[0];
          $owner = "[NA]";
          $group = "[NA]";
          $size = "0";
          $perms = "0777";
          $sum = "0";
          $pkgs  = join (" ", (splice @ar, 3, $#ar - 2));
        }

        printf "INS|%s|%s|%s|%s|%s|%s|%s|%s|%s\n",
               $type, $perms, $owner, $group, $size, $name, $sum, $target, $pkgs;
        next A;
      }
    }
  }
  close FIL; 
}
