package CatalystX::Controller::reCAPTCHA;
use strict;
use warnings;
use base 'Catalyst::Controller';
use Captcha::reCAPTCHA;
our $VERSION = '0.1';


sub captcha_get : Private {
    my ($self, $c) = @_;
    my $cap = Captcha::reCAPTCHA->new;
    $c->stash->{recaptcha} = $cap->get_html($c->config->{recaptcha}->{pub_key});
}

sub captcha_check : Private {
    my ($self, $c) = @_;
    my $cap = Captcha::reCAPTCHA->new;
    my $result = {};
    if ( $c->req->param( 'recaptcha_response_field' ) ) {
        $result = $cap->check_answer(
            $c->config->{recaptcha}->{priv_key}, $ENV{'REMOTE_ADDR'},
            $c->req->param('recaptcha_challenge_field'),
            $c->req->param('recaptcha_response_field')
        );
    }
    else {
        $c->stash->{recaptcha_ok} = "User appears not to have submitted a recaptcha";
    }

    if ( $result->{is_valid} ) {
        $c->stash->{recaptcha_ok} = 1;
    }
    else {
        $c->stash->{recaptcha_ok} = $result->{error};
    }
}



=head1 NAME

CatalystX::Controller::reCAPTCHA - authenticate people and read books!

=head1 SUMMARY

Catalyst::Controller wrapper around L<Capatcha::reCAPTCHA>.  Provides
a number of C<Private> methods that deal with the recaptcha.

=head2 CONFIGURATION

In MyApp.pm (or equivalent in config file):

 __PACKAGE__->config->{recaptcha}->{pub_key} = '6LcsbAAAAAAAAPDSlBaVGXjMo1kJHwUiHzO2TDze';
 __PACKAGE__->config->{recaptcha}->{priv_key} = '6LcsbAAAAAAAANQQGqwsnkrTd7QTGRBKQQZwBH-L';

(the two keys above work for http://localhost).

=head2 METHOD

captcha_get : Private

Sets $c->stash->{recaptcha} to be the html form for the L<http://recaptcha.net/> reCAPTCHA service which can be included in your HTML form.

=head2 METHOD

captcha_check : Private

Validates the reCaptcha using L<Captcha::reCAPTCHA>.  sets
$c->stash->{recaptcha_ok} which will be 1 on success or an error
string provided by L<Captcha::reCAPTCHA> on failure.

=head2 EXAMPLES

See the t/lib/TestApp example in the
L<CatalystX::Controller::reCAPTCHA> distribution.

=head1 SEE ALSO

L<Captcha::reCAPTCHA>, L<Catalyst::Controller>, L<Catalyst>.

=head1 AUTHOR and Copyright

Kieren Diment L<zarquon@cpan.org>.

=head1 LICENCE

This library is free software, you can redistribute it and/or modify it under
the same terms as Perl itself.

=cut

1;
