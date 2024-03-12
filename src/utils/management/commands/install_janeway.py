import os

from django.conf import settings
from django.core.management.base import BaseCommand
from django.core.management import call_command
from django.db import transaction
from django.utils import translation
from django.core.exceptions import ImproperlyConfigured

from press import models as press_models
from journal import models as journal_models
from utils.install import (
        update_issue_types,
        update_settings,
        update_xsl_files,
)
from utils import shared

ROLES_RELATIVE_PATH = 'utils/install/roles.json'

class Command(BaseCommand):
    """
    Installs a press and oe journal for Janeway.
    """

    help = "Installs a press and oe journal for Janeway."

    def add_arguments(self, parser):
        parser.add_argument(
            '-d', '--dry-run',
            action='store_true',
            dest='dry_run',
            default=False,
            help='Rolls back the transaction resulting from this command'
        )
        parser.add_argument(
            '--use-defaults',
            action='store_true',
            dest='use_defaults',
            default=False,
            help='Avoids requesting user input and uses default details (defaults can be set with environment variables)'
        )
        parser.add_argument(
            '--press_name',
            dest='press_name',
            default=os.getenv("JANEWAY_PRESS_NAME", default='Press'),
            help='Specifies the Press Name to use when installing Janeway'
        )
        parser.add_argument(
            '--press_domain',
            dest='press_domain',
            default=os.getenv("JANEWAY_PRESS_DOMAIN", default='localhost'),
            help='Specifies the Press Domain to use when installing Janeway'
        )
        parser.add_argument(
            '--press_contact',
            dest='press_contact',
            default=os.getenv("JANEWAY_PRESS_CONTACT", default='dev@noemail.com'),
            help='Specifies the Press Contact email address to use when installing Janeway'
        )
        parser.add_argument(
            '--journal_code',
            dest='journal_code',
            default=os.getenv("JANEWAY_JOURNAL_CODE", default='Journal'),
            help='Specifies the Journal Code to use when installing Janeway'
        )
        parser.add_argument(
            '--journal_name',
            dest='journal_name',
            default=os.getenv("JANEWAY_JOURNAL_NAME", default='Test Journal'),
            help='Specifies the Journal Name to use when installing Janeway'
        )
        parser.add_argument(
            '--journal_domain',
            dest='journal_domain',
            default=os.getenv("JANEWAY_JOURNAL_DOMAIN", default=''),
            help='Specifies the Journal Domain to use when installing Janeway (optional)'
        )
        parser.add_argument(
            '--journal_description',
            dest='journal_description',
            default=os.getenv("JANEWAY_JOURNAL_DESCRIPTION", default='Journal #1 description'),
            help='Specifies the Journal Description to use when installing Janeway'
        )

    def handle(self, *args, **options):
        """Installs Janeway

        :param args: None
        :param options: dict
        :return: None
        """

        # As of v1.4 USE_I18N must be enabled.
        if not settings.USE_I18N:
            raise ImproperlyConfigured("USE_I18N must be enabled from v1.4 of Janeway.")
        use_defaults = options["use_defaults"]

        call_command('migrate')
        print("Please answer the following questions.\n")
        translation.activate('en')
        with transaction.atomic():
            press = press_models.Press.objects.first()
            if not press:
                press = press_models.Press()
                if use_defaults:
                    press.name = options['press_name']
                    press.domain = options['press_domain']
                    press.main_contact= options['press_contact']
                else:
                    press.name = input('Press name: ')
                    press.domain = input('Press domain: ')
                    press.main_contact = input('Press main contact (email): ')
                press.save()

            print("Thanks! We will now set up our first journal.\n")
            print("Installing settings and XSL fixtures... ", end="")
            update_xsl_files()
            update_settings()
            print("[okay]")
        try:
            columns = os.get_terminal_size().columns
            print(columns)
            if columns <= 144:
                print(JANEWAY_ASCII_SMALL)
            else:
                print(JANEWAY_ASCII)
        except Exception:
            print(JANEWAY_ASCII_SMALL)


JANEWAY_ASCII = """


                                                                ################
                                                           #######            #######
                                                       #####                        #####
                                                    ####                                ####
                                                  ####                                    ####
                                                ###                                          ###
                                              ####                                            %###
                                             ###                                                ###
                                            ###                                                  ###
                                           ##                                                      ##
                                          ##                                                        ##
                                         ###                                                         ##

            ####        ####          ####             ###   #################  ####           ####           ####    ####   #####         #####
            ####       ######         ######           ###   #################   ####         ######         ####    ######    ####       #####
            ####      ########        ########         ###   ####                 ####       ########       ####    ########    ####     ####
            ####     ####  ####       #### #####       ###   ####                 ####      ####  ###      ####    ###%  ####    ####   ####
            ####    ####    ####      ####   #####     ###   ###############       ####     ###   ####     ####   ####    ####    #### ####
            ####   ####      ###      ####     #####   ###   ###############        ####   ####    ####   ####   ####      ###     #######
####        ####  ###############     ####       ####% ###   ####                    #### ####      ###  ####   ###############      ###
#####      ####   ################    ####        ########   ####                     ### ###        #######    ################     ###
 #############   #####        #####   ####          ######   #################        #######        ######    #####        #####    ###
    #######     ####            ####  ####            ####   #################         #####          #####   ####            ####   ###

                                         ###                                                         ##
                                          ##                                                        ##
                                           ##                                                      ##
                                            ###                                                  ###
                                             ###                                                ###
                                              ####                                             ###
                                                ###                                          ###
                                                  ####                                    ####
                                                    ####                                ####
                                                       #####                        #####
                                                           #######            #######
                                                                ################


"""

JANEWAY_ASCII_SMALL = """
                                  @@@@@@@@@@@@
                              @@@              @@@
                            @                      @
                          @                          @
                        @@                            @@
                       @@                              @@

       @@    @@@     @@@      @@  @@@@@@@@@  @@     @@@      @@  @@@  @@     @@
       @@   @@ @@    @@@@@    @@  @@          @@    @@@@    @@  @@ @@  @@@  @@
       @@  @@   @@   @@  @@@  @@  @@@@@@@@    @@@  @@  @@  @@  @@   @@   @@@@
@@    @@@ @@@@@@@@@  @@    @@@@@  @@           @@ @@    @@@@  @@@@@@@@@   @@
 @@@@@@@ @@@     @@@ @@      @@@  @@@@@@@@@     @@@     @@@@ @@@     @@@  @@

                       @@                              @@
                        @@                            @@
                          @                          @
                            @                      @
                              @@@              @@@
                                  @@@@@@@@@@@@
"""
