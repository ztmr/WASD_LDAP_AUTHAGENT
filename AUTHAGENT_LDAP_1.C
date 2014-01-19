/*****************************************************************************/
/*
                             authagent_LDAP_1.c

     *** THIS VERSION USES THE LDAP SERVER TO DO THE AUTHENTICATION ***

LDAP authentication agent CGIplus script, using the callout mechanism.

Code adapted from the OpenVMS Utility Routines Manual, Sample LDAP API Code.

Uses the integrated LDAP run-time support available with VMS V7.3 and later.

Requires the HP SSL Package to be installed and started.

Attempts to improve performance by remaining connected to the last accessed
LDAP server.  If the server host or port changes between authentication
requests (which is generally unlikely) the agent unbinds from the currently
connected LDAP server before connecting to the new.  If there are any 'hard'
errors while processing (e.g. broken connection) the agent unbinds and retries.

Parameters can be passed in the command-line or the HTTPD$AUTH param=
directive, or a combination of both.  Agent persistence means parameters set
remain set until use of the same parameter (qualifier) again overwriting the
previous value, or until the /RESET qualifier is encountered.  This resets the
values of *all* parameters to the default values.  Hence, basic parameters such
as host and port, and perhaps simple binding parameters, may be established at
the command-line (perhaps using a wrapper DCL procedure) and then each
authorization request could vary that as necessary using HTTPD$AUTH param=
directives.  Care must be exercised that one does not interfere with another.
In general though most LDAP agent parameters can just be passed through from
the authorization rule with each request (see example below).

The filter implements the '%u' and '%d' conversion characters to allow complex
expressions to be built using the userid and realm from the user credentials.

Verifies the password once the initial search for the entry has completed
successfully by attempting an authenticated (re-)bind using the entry's 'dn'
and the password supplied from the browser with the request.  If the bind
succeeds then the password was correct!  (Many thanks to Jeremy Begg for
pointing out this is how LDAP agents perform authentication and that this
obviates the need for any 'privileged' credentials associated with the LDAP
client.)

If the password verifies the 'uid' is used as the VMS username.

If the entry did not contain a 'uid' and a default username has been configured
(using the /UDEF="<string>" parameter) this is substituted as the authenticated
VMS username.


RUN-TIME PARAMETERS
-------------------
These parameters are used to pass run-time information to the authentication
agent from the authorization configuration (see Authentication Configuration
below).

/BASE=<string>           ldap_search_s() 'base' string
/CERT=<file-spec>        client certificate and private key (if files are
                           protected may need to be INSTALLed with SYSPRV)
/DATT=<string>           LDAP attribute containing the user detail for the
                           AUTH_USER variable (defaults to 'displayName')
/FILTER=<string>         ldap_search_s() 'filter' string
                           (implements the '%u' and '%d' conversions)
/PORT=<integer>          optional method for specifying LDAP server port
/RESET                   reset the parameters (in persistent environments
                           parameters can remain across uses)
/SERVER=<host[:port]>    host name and optional port number for LDAP server
/SSL[=<integer>]         use LDAPS (deprecated SSL) and optionally specify
                           the SSL protocol (default 1; 20, 23, 30, 31, etc)
/TLS[=<integer>]         use LDAP TLS (current SSL) and optionally specify
                           the SSL protocol (default 1; 20, 23, 30, 31, etc.)
/UDEF=<string>           default VMS username when entry found and password
                           validated but no uid available
/UATT=<string>           LDAP attribute name containing VMS username
                           (defaults to 'uid' attribute)
/VERSION=<integer>       LDAP protocol version (defaults to 3)


COMMAND-LINE PARAMETERS
-----------------------
In addition to the run-time parameters these are available at the command-line.

/AUTH_PASSWORD=<string>  emulates CGI environment AUTH_PASSWORD variable
/DBUG                    low level debug statements
/DUMP                    output the detail of matching entries
/REMOTE_USER=<string>    emulates CGI environment REMOTE_USER variable
/WATCH                   output WASD server WATCH-able statements


AUTHENTICATION CONFIGURATION
----------------------------
The run-time parameters CAN be passed via a 'param=' argument to the HTTPD$AUTH
configuration for the realm.

  ["Just an LDAP Example"=AUTHAGENT_LDAP=agent]

  /an/example/path/* r+w,param='\
  /HOST="ldap.host.domain"/TLS/BASE="dc=domain,DC=au"/FILTER="uid=%u"'


COMMAND-LINE CHECKING
---------------------
Most functionality may be checked from the command-line using (almost) exactly
the same syntax and parameters as used in the authentication (CGIplus) mode. 
This allows the format and syntax of the authentication configuration to be
developed and tested interactively.  In addition, and for general information,
queries not possible (e.g. using wildcards) in the authentication mode may be
used in the command-line mode.

  $ LDAPAGE == "$WASD_EXE:AUTHAGENT_LDAP /WATCH"
  $ LDAPAGE /DUMP /HOST="ldap.fnal.gov" /BASE="o=fnal" /FILTER="cn=*smith*"
  $ LDAPAGE /HOST="ldap.host.domain" /BASE="dc=domain,DC=au" -
            /FILTER="uid=%u" /REMOTE_USER="whatever"


PRIVILEGED IMAGE
----------------
To use an SSL certificate/key file that is protected against the account the
agent is executing under the image must be installed with SYSPRV.

  $ INSTALL REPLACE <directory>:AUTHAGENT_LDAP.EXE /AUTHPRIV=SYSPRV


LOGICAL NAMES
-------------
AUTHAGENT_LDAP$DBUG       same as /DBUG
AUTHAGENT_LDAP$WATCH      same as /WATCH


BUILD DETAILS
-------------
Compile then link:
  $ @BUILD_AUTHAGENT_LDAP
To just link:
  $ @BUILD_AUTHAGENT_LDAP LINK


SPONSOR
-------
This software has been developed under the sponsorship of the University of
Malaga and generously made available to the wider WASD community.  Many thanks.


COPYRIGHT
---------
Copyright (C) 2006-2007 Mark G.Daniel
This program, comes with ABSOLUTELY NO WARRANTY.
This is free software, and you are welcome to redistribute it
under the conditions of the GNU GENERAL PUBLIC LICENSE, version 2.


VERSION HISTORY (update SOFTWAREVN as well)
---------------
11-MAY-2007  MGD  v1.0.1, belt-and-braces
18-JUL-2006  MGD  v1.0.0, initial (re)development
*/

/*****************************************************************************/

#define SOFTWAREVN "1.0.1"
#define SOFTWARENM "AUTHAGENT_LDAP"
#ifdef __ALPHA
#  define SOFTWAREID SOFTWARENM " AXP-" SOFTWAREVN
#endif
#ifdef __ia64
#  define SOFTWAREID SOFTWARENM " IA64-" SOFTWAREVN
#endif
#ifdef __VAX
#  define SOFTWAREID SOFTWARENM " VAX-" SOFTWAREVN
#endif

#ifndef __VAX
#   pragma nomember_alignment
#endif

/* standard C header files */
#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* VMS related header files */
#include <descrip.h>
#include <jpidef.h>
#include <libdef.h>
#include <lib$routines.h>
#include <lnmdef.h>
#include <prvdef.h>
#include <ssdef.h>
#include <starlet.h>
#include <stsdef.h>

/* application header files */
#include <ldap.h> 
#include <cgilib.h>

#define VMSok(x) ((x) & STS$M_SUCCESS)
#define VMSnok(x) !(((x) & STS$M_SUCCESS))

#define BOOL int
#define TRUE 1
#define FALSE 0

#define DEFAULT_ATTRIBUTE_USERNAME "uid"
#define DEFAULT_ATTRIBUTE_DISPLAY "displayName"

#define DEFAULT_SSL_PORT 636

/******************/
/* global storage */
/******************/

char  Utility [] = "AUTHAGENT_LDAP";

BOOL  Debug,
      DebugWatch;

int  LdapProtocolVersion = LDAP_VERSION3,
     LdapSSL,
     StartTLS;

unsigned short  LdapPort;

char  *AuthAgentPtr,
      *RemoteUserPtr;

char  CertKeyFileName [128],
      CliRemoteUser [48],
      CliAuthPassword [48],
      DnValue [256],
      LdapBase [128],
      LdapFilter [128],
      LdapHost [128],
      SoftwareID [96],
      UserDisplayAttribute [64] = DEFAULT_ATTRIBUTE_DISPLAY,
      UserDisplayValue [64],
      UserNameAttribute [64] = DEFAULT_ATTRIBUTE_USERNAME,
      UserNameDefault [64],
      UserNameValue [64],
      VmsUserName [48];

unsigned long  SysPrvMask [2] = { PRV$M_SYSPRV, 0 };

/***********************/
/* function prototypes */
/***********************/

void GetParameters ();
void GetRunTimeParameters (char*, BOOL);
void NeedsPrivilegedAccount ();
BOOL ProcessRequest ();
char* SysTrnLnm (char*, char*);
char* WatchElapsed ();
void WatchThis (int, char*, ...);
int strzcpy (char*, char*, int);
BOOL strsame (char*, char*, int);

/*****************************************************************************/
/*
*/

main ()

{
   BOOL  ok;
   char  *cptr;

   /*********/
   /* begin */
   /*********/

   sprintf (SoftwareID, "%s (%s)", SOFTWAREID, CgiLibEnvironmentVersion());

   Debug = (SysTrnLnm ("AUTHAGENT_LDAP$DBUG", NULL) != NULL);
   CgiLibEnvironmentSetDebug (Debug);

   GetParameters ();

   CgiLibEnvironmentInit (0, NULL, FALSE);

   if (!SysTrnLnm ("HTTP$INPUT", NULL))
   {
      /* not in a server context (interactive, command-line testing) */
      NeedsPrivilegedAccount ();
      if (DebugWatch) WatchElapsed ();
      ProcessRequest ();
      if (DebugWatch) WatchThis (__LINE__, "ELAPSED %s", WatchElapsed());
      exit (SS$_NORMAL);
   }

   /* MUST only be executed in a CGIplus environment! */
   if (!CgiLibEnvironmentIsCgiPlus ())
      exit (SS$_ABORT);

   for (;;)
   {
      /* block waiting for the next request */
      CgiLibVar ("");

      /* provide the server attention "escape" sequence record */
      if (!Debug) CgiLibCgiPlusESC ();

      DebugWatch = (SysTrnLnm ("AUTHAGENT_LDAP$WATCH", NULL) != NULL);

      if (DebugWatch) WatchElapsed ();

      /* ensure this is being invoked by the server */
      if (!(AuthAgentPtr = CgiLibVarNull ("AUTH_AGENT"))) exit (SS$_ABORT);
      if (DebugWatch) WatchThis (__LINE__, "AUTH_AGENT %s", AuthAgentPtr);

      WatchThis (__LINE__, "Pre-callout...");
      /* belt and braces */
      //fprintf (stdout, "100 AUTHAGENT-CALLOUT\n");
      //fflush (stdout);

      /* have at least two goes at authenticating the user */
      WatchThis (__LINE__, "Gonna to process request...");
      if (!(ok = ProcessRequest ())) ok = ProcessRequest ();
      WatchThis (__LINE__, "Request finished...");

      if (!ok)
      {
         fprintf (stdout, "500 LDAP authenticator.\n");
         fflush (stdout);
      }

      if (DebugWatch) WatchThis (__LINE__, "ELAPSED %s", WatchElapsed());

      /* provide the "escape" end-of-text sequence record */
      if (!Debug) CgiLibCgiPlusEOT ();

      CgiLibCgiPlusEOF ();

      if (!ok) exit (SS$_NORMAL);
   }
}

/*****************************************************************************/
/*
Main authentication request processing function.
*/

BOOL ProcessRequest ()
       
{
   static BOOL  ServerUnbind;
   static char  ConnectedLdapHost [128];
   static short  ConnectedLdapPort;
   static LDAP  *ld; 

   BOOL  PasswordOK;
   int  idx, rc, status,
        EntryCount; 
   char  *attptr, *dnptr,
         *cptr, *sptr, *tptr, *zptr,
         *PasswordPtr;
   char  UserFilter [256],
         UserId [64],
         UserRealm [128];
   char  *AttribArray [3];
   LDAPMessage  *resptr, *entptr; 
   BerElement  *berptr; 
   char  **AttValues; 

   /*********/
   /* begin */
   /*********/

   if (Debug) fprintf (stdout, "ProcessRequest()\n");

   if (DebugWatch) WatchThis (__LINE__, "%s", SoftwareID);

   if (AuthAgentPtr) GetRunTimeParameters (AuthAgentPtr, FALSE);

   AttribArray[0] = UserDisplayAttribute;
   AttribArray[1] = UserNameAttribute;
   AttribArray[2] = NULL;

   if (CgiLibEnvironmentIsCgiPlus())
   {
      RemoteUserPtr = CgiLibVarNull ("REMOTE_USER");
      if (!RemoteUserPtr)
      {
         if (DebugWatch) WatchThis (__LINE__, "REMOTE_USER?");
         return (FALSE); 
      }
   }
   else
      RemoteUserPtr = CliRemoteUser;

   /* ensure no covert expressions sneak in under the radar */
   for (cptr = RemoteUserPtr; *cptr; cptr++)
      if (*cptr == '*' || *cptr == '&' || *cptr == '|' || 
          *cptr == '!' || *cptr == '(' || *cptr == ')' ||
          *cptr == '\\') break;
   if (*cptr)
   {
      if (DebugWatch) WatchThis (__LINE__, "REMOTE_USER wildcard/expression!");
      fprintf (stdout, "401 ambiguous credentials.\n");
      fflush (stdout);
      return (TRUE); 
   }

   if (CliAuthPassword[0])
      PasswordPtr = CliAuthPassword;
   else
      PasswordPtr = CgiLibVarNull ("AUTH_PASSWORD");
   if (!PasswordPtr)
   {
      if (DebugWatch) WatchThis (__LINE__, "AUTH_PASSWORD?");
      return (FALSE); 
   }

   /********************/
   /* build the filter */
   /********************/

   zptr = (sptr = UserId) + sizeof(UserId)-1;
   for (cptr = RemoteUserPtr;
        *cptr && *cptr != '@' && sptr < zptr;
        *sptr++ = *cptr++);
   *sptr = '\0';

   if (*cptr) cptr++;
   zptr = (sptr = UserRealm) + sizeof(UserRealm)-1;
   while (*cptr && sptr < zptr) *sptr++ = *cptr++;
   *sptr = '\0';

   /* implement '%u' for userid and '%d' for realm */
   zptr = (sptr = UserFilter) + sizeof(UserFilter)-1;
   cptr = LdapFilter;
   while (*cptr && sptr < zptr)
   {
      while (*cptr && *cptr != '%' && sptr < zptr) *sptr++ = *cptr++;
      if (!*cptr) break;
      cptr++;
      if (!*cptr) break;
      if (*cptr == 'u')
      {
         cptr++;
         for (tptr = UserId; *tptr && sptr < zptr; *sptr++ = *tptr++);
      }
      else
      if (*cptr == 'd')
      {
         cptr++;
         for (tptr = UserRealm; *tptr && sptr < zptr; *sptr++ = *tptr++);
      }
      else
         /* unknown conversion character, just ignore it */
         *sptr++ = *cptr++;
   }
   *sptr = '\0';

   /* just override the above if from the command-line and no remote user */
   if (!CgiLibEnvironmentIsCgiPlus() && !CliRemoteUser[0])
      strzcpy (UserFilter, LdapFilter, sizeof(UserFilter));

   if (DebugWatch) WatchThis (__LINE__, "FILTER |%s|", UserFilter);

   /******************************/
   /* connect to the LDAP server */
   /******************************/

   /* check if we need to change any persistent connection */ 
   if ((ConnectedLdapHost[0] && strcmp (LdapHost, ConnectedLdapHost)) ||
       (ConnectedLdapPort && ConnectedLdapPort != LdapPort))
      ServerUnbind = TRUE;

   if (ServerUnbind)
   {
      if (DebugWatch)
         WatchThis (__LINE__, "ldap_unbind() %s:%d",
                    ConnectedLdapHost, ConnectedLdapPort);

      rc = ldap_unbind (ld); 

      if (DebugWatch)
         if (rc != LDAP_SUCCESS)
            WatchThis (__LINE__, "ERROR %d %d %%X%08.08X %s",
                       rc, errno, vaxc$errno, ldap_err2string(rc)); 

      ServerUnbind = FALSE;
      ConnectedLdapHost[0] = '\0';
      ConnectedLdapPort = 0;
   }

   if (ConnectedLdapHost[0])
   {
      /* already connected to the required server */
      if (DebugWatch)
         WatchThis (__LINE__, "persistent %s:%d",
                    ConnectedLdapHost, ConnectedLdapPort);

      /* cancel any previous authentication credentials */
      rc = ldap_simple_bind_s (ld, NULL, NULL);
      if (rc != LDAP_SUCCESS)
      { 
         if (DebugWatch)
            WatchThis (__LINE__, "ERROR %d %d %%X%08.08X %s",
                       rc, errno, vaxc$errno, ldap_err2string(rc)); 
         ServerUnbind = TRUE;
         return (FALSE); 
      }
   }
   else
   {
      strzcpy (ConnectedLdapHost, LdapHost, sizeof(ConnectedLdapHost));
      ConnectedLdapPort = LdapPort;
      if (!ConnectedLdapPort)
         if (!LdapSSL)
            ConnectedLdapPort = LDAP_PORT;
         else
            ConnectedLdapPort = DEFAULT_SSL_PORT;

      if (DebugWatch)
         WatchThis (__LINE__, "ldap_init() %s:%d",
                    ConnectedLdapHost, ConnectedLdapPort);

      ld = ldap_init (ConnectedLdapHost, ConnectedLdapPort);
      if (ld == NULL) 
      {
         if (DebugWatch)
            WatchThis (__LINE__, "ERROR %d %%X%08.08X", errno, vaxc$errno); 
         ServerUnbind = TRUE;
         return (FALSE); 
      }

      ldap_set_option (ld, LDAP_OPT_PROTOCOL_VERSION, &LdapProtocolVersion);

      if (StartTLS || LdapSSL)
      {
         /******************/
         /* secure sockets */
         /******************/

         ldap_set_option (ld, LDAP_OPT_TLS_VERSION,
                          StartTLS ? &StartTLS : &LdapSSL);

         if (CertKeyFileName[0])
         {
            ldap_set_option (ld, LDAP_OPT_TLS_CERT_FILE, CertKeyFileName);
            ldap_set_option (ld, LDAP_OPT_TLS_PKEY_FILE, CertKeyFileName);

            /* turn on SYSPRV to allow access to possibly protected files */
            status = sys$setprv (1, &SysPrvMask, 0, 0);
            if (DebugWatch)
               if (VMSnok(status) || status == SS$_NOTALLPRIV)
                  WatchThis (__LINE__, "sys$setprv() %%X%08.08X\n", status);
         }

         if (DebugWatch)
            WatchThis (__LINE__, "ldap_tls_start() %s:%d",
                       StartTLS ? "StartTLS" : "LDAPS",
                       StartTLS ? StartTLS : LdapSSL);

         rc = ldap_tls_start (ld, StartTLS ? 1 : 0);

         /* turn off SYSPRV */
         if (CertKeyFileName[0]) sys$setprv (0, &SysPrvMask, 0, 0);

         if (rc != LDAP_SUCCESS)
         {
            if (DebugWatch)
               WatchThis (__LINE__, "ERROR %d %d %%X%08.08X %s",
                          rc, errno, vaxc$errno, ldap_err2string(rc)); 
            ServerUnbind = TRUE;
            return (FALSE); 
         }
      }
   }

   /******************/
   /* make the query */
   /******************/

   if (DebugWatch)
      WatchThis (__LINE__, "ldap_search_s() |%s|%s|", LdapBase, UserFilter);

   rc = ldap_search_s (ld,
                       LdapBase, 
                       LDAP_SCOPE_SUBTREE,
                       UserFilter,
                       AttribArray, 0,
                       &resptr);

   if (rc != LDAP_SUCCESS)
   { 
      if (DebugWatch)
         WatchThis (__LINE__, "ERROR %d %d %%X%08.08X %s",
                    rc, errno, vaxc$errno, ldap_err2string(rc)); 
      ServerUnbind = TRUE;
      return (FALSE); 
   } 

   /*******************/
   /* process results */
   /*******************/

   EntryCount = 0;
   DnValue[0] = '\0';

   for (entptr = ldap_first_entry (ld, resptr);
        entptr != NULL; 
        entptr = ldap_next_entry (ld, entptr))
   { 
      EntryCount++;
      dnptr = ldap_get_dn (ld, entptr); 
      if (DebugWatch) WatchThis (__LINE__, "ENTRY %d |%s|", EntryCount, dnptr); 
      strzcpy (DnValue, dnptr, sizeof(DnValue));
      ldap_memfree (dnptr); 
   }

   /* free the search results (let's hope it doesn't leak too much!) */ 
   ldap_msgfree (resptr); 

   if (!EntryCount)
   {
      /*************/
      /* not found */
      /*************/

      if (DebugWatch) WatchThis (__LINE__, "NOT FOUND");
      fprintf (stdout, "401 authentication failure.\n");
      fflush (stdout);
      return (TRUE); 
   }
   else
   if (EntryCount > 1)
   {
      /********************/
      /* ambiguous result */
      /********************/

      if (DebugWatch) WatchThis (__LINE__, "AMBIGUOUS");
      return (FALSE); 
   }

   /*************************/
   /* bind with credentials */
   /*************************/

   if (DebugWatch)
      WatchThis (__LINE__, "ldap_simple_bind_s() %s", DnValue);

   rc = ldap_simple_bind_s (ld, DnValue, PasswordPtr);

   if (rc == LDAP_INVALID_CREDENTIALS)
   {
      /**************************/
      /* password verify failed */
      /**************************/

      if (DebugWatch) WatchThis (__LINE__, "FAILED");
      fprintf (stdout, "401 authentication failure.\n");
      fflush (stdout);
      return (TRUE); 
   }
   else
   if (rc != LDAP_SUCCESS)
   {
      if (DebugWatch)
         WatchThis (__LINE__, "ERROR %d %d %%X%08.08X %s",
                    rc, errno, vaxc$errno, ldap_err2string(rc)); 
      ServerUnbind = TRUE;
      return (FALSE); 
   }

   /******************/
   /* get attributes */
   /******************/

   if (DebugWatch)
      WatchThis (__LINE__, "ldap_search_s() |%s|%s|", LdapBase, UserFilter);

   rc = ldap_search_s (ld,
                       LdapBase, 
                       LDAP_SCOPE_SUBTREE,
                       UserFilter,
                       AttribArray, 0,
                       &resptr);

   if (rc != LDAP_SUCCESS)
   { 
      if (DebugWatch)
         WatchThis (__LINE__, "ERROR %d %d %%X%08.08X %s",
                    rc, errno, vaxc$errno, ldap_err2string(rc)); 
      ServerUnbind = TRUE;
      return (FALSE); 
   } 

   /*******************/
   /* process results */
   /*******************/

   UserDisplayValue[0] = UserNameValue[0] = '\0';

   EntryCount = 0;
   for (entptr = ldap_first_entry (ld, resptr);
        entptr != NULL; 
        entptr = ldap_next_entry (ld, entptr))
   { 
      EntryCount++;
      dnptr = ldap_get_dn (ld, entptr); 
      if (DebugWatch) WatchThis (__LINE__, "ENTRY %d |%s|", EntryCount, dnptr); 
      ldap_memfree (dnptr); 

      for (attptr = ldap_first_attribute (ld, entptr, &berptr);
           attptr != NULL; 
           attptr = ldap_next_attribute (ld, entptr, berptr))
      { 
         AttValues = ldap_get_values (ld, entptr, attptr); 
         for (idx = 0; AttValues[idx] != NULL; idx++)
         {
           if (DebugWatch)
                  WatchThis (__LINE__, "ATTRIBUTE |%s|%s|",
                             attptr, AttValues[idx]);
            if (!strcmp (UserDisplayAttribute, attptr))
               strzcpy (UserDisplayValue, AttValues[idx],
                        sizeof(UserDisplayValue));
            else
            if (!strcmp (UserNameAttribute, attptr))
               strzcpy (UserNameValue, AttValues[idx],
                        sizeof(UserNameValue));
         }
         ldap_value_free (AttValues); 
         ldap_memfree (attptr); 
      } 

      if (berptr != NULL) ber_free (berptr, 0); 
   }

   /* free the search results (let's hope it doesn't leak too much!) */ 
   ldap_msgfree (resptr); 

   if (EntryCount != 1)
   {
      /**************/
      /* what's up? */
      /**************/

      if (DebugWatch) WatchThis (__LINE__, "BUGCHECK");
      ServerUnbind = TRUE;
      return (FALSE); 
   }

   if (!UserNameValue[0])
   {
      /********************/
      /* 'uid' attribute? */
      /********************/

      if (UserNameDefault[0])
      {
         if (DebugWatch)
            WatchThis (__LINE__, "DEFAULT %s", UserNameDefault);
         strzcpy (UserNameValue, UserNameDefault, sizeof(UserNameValue));
      }
      else
      {
         /* no username ('uid') and no default to fall back on */
         if (DebugWatch) WatchThis (__LINE__, "USERNAME? (/UATT=)");
         ServerUnbind = TRUE;
         return (FALSE);
      }
   }

   /************/
   /* finally! */
   /************/

   //fprintf (stdout, "100 VMS-USER %s\n", UserNameValue);
   //fprintf (stdout, "100 VMS-USER HTTP$LDAP\n");
   fprintf (stdout, "100 VMS-USER %s\n", UserNameDefault);
   fflush (stdout);

   if (UserDisplayValue[0])
   {
      /* must be done following VMS-USER which also sets USER! */
      fprintf (stdout, "100 USER %s\n", UserDisplayValue);
      fflush (stdout);
   }

   return (TRUE);
}

/*****************************************************************************/
/*
Prevent the great unwashed from pillaging the treasures within!
*/ 

void NeedsPrivilegedAccount ()

{
   static unsigned long  PrivAcctMask [2] = { PRV$M_SETPRV | PRV$M_SYSPRV, 0 };

   static long  Pid = -1;
   static unsigned long  JpiAuthPriv [2];

   static struct
   {
      unsigned short  buf_len;
      unsigned short  item;
      void  *buf_addr;
      void  *ret_len;
   }
      JpiItems [] =
   {
      { sizeof(JpiAuthPriv), JPI$_AUTHPRIV, &JpiAuthPriv, 0 },
      {0,0,0,0}
   };

   int  status;

   /*********/
   /* begin */
   /*********/

   if (Debug) fprintf (stdout, "NeedsPrivilegedAccount()\n");

   status = sys$getjpiw (0, &Pid, 0, &JpiItems, 0, 0, 0);
   if (VMSnok (status)) exit (status);

   if (!(JpiAuthPriv[0] & PrivAcctMask[0])) exit (SS$_NOSYSPRV);
}

/*****************************************************************************/
/*
Output and flush a record suitable for WASD to WATCH in callout mode.
*/ 

void WatchThis
(
int SourceCodeLine,
char *FormatString,
...
)
{
   static unsigned long  PrevBinTime [2];
   static char  TimeString [12];
   static $DESCRIPTOR (TimeFaoDsc, "!2ZL:!2ZL:!2ZL.!2ZL\0");
   static $DESCRIPTOR (TimeStringDsc, TimeString);

   int  argcnt;
   unsigned long  BinTime [2];
   unsigned short  NumTime [7];
   va_list  argptr;

   /*********/
   /* begin */
   /*********/

   if (Debug) fprintf (stdout, "WatchThis()\n");

   sys$gettim (&BinTime);
   if (BinTime[0] != PrevBinTime[0] ||
       BinTime[1] != PrevBinTime[1])
   {
      PrevBinTime[0] == BinTime[0];
      PrevBinTime[1] == BinTime[1];
      sys$numtim (&NumTime, &BinTime);
      sys$fao (&TimeFaoDsc, NULL, &TimeStringDsc,
               NumTime[3], NumTime[4], NumTime[5], NumTime[6]);
   }

   fprintf (stdout, "000 [%d] %s ", SourceCodeLine, TimeString);
   va_count (argcnt);
   va_start (argptr, FormatString);
   vprintf (FormatString, argptr);
   fputs ("\n", stdout);
   fflush (stdout);
}

/*****************************************************************************/
/*
Return a pointer to a string showing the elapsed time (for WATCHing).
*/ 

char* WatchElapsed ()

{
   static unsigned long  StatTimerContext;
   static unsigned long  StatTimerElapsedTime = 1;
   static char  ElapsedTime [24];
   static $DESCRIPTOR (ElapsedFaoDsc, "!%D\0");
   static $DESCRIPTOR (ElapsedTimeDsc, ElapsedTime);

   int  status;
   unsigned long  ElapsedBinTime [2];

   /*********/
   /* begin */
   /*********/

   if (Debug) fprintf (stdout, "WatchElapsed()\n");

   if (StatTimerContext)
   {
      status = lib$stat_timer (&StatTimerElapsedTime,
                               &ElapsedBinTime,
                               &StatTimerContext);
      if (VMSnok (status)) exit (status);

      sys$fao (&ElapsedFaoDsc, NULL, &ElapsedTimeDsc, &ElapsedBinTime);
      memmove (ElapsedTime, ElapsedTime+5, 12);

      status = lib$free_timer (&StatTimerContext);
      if (VMSnok (status)) exit (status);
      StatTimerContext = 0;

      return (ElapsedTime);
   }

   /* initialize statistics timer */
   status = lib$init_timer (&StatTimerContext);
   if (VMSnok (status)) exit (status);

   return (NULL);
}

/*****************************************************************************/
/*
Translate a logical name using LNM$FILE_DEV. Return a pointer to the value
string, or NULL if the name does not exist.  If 'LogValue' is supplied the
logical name is translated into that (assumed to be large enough), otherwise
it's translated into an internal static buffer.
*/

char* SysTrnLnm
(
char *LogName,
char *LogValue
)
{
   static unsigned short  ShortLength;
   static char  StaticLogValue [256];
   static $DESCRIPTOR (LogNameDsc, "");
   static $DESCRIPTOR (LnmFileDevDsc, "LNM$FILE_DEV");
   static struct {
      short int  buf_len;
      short int  item;
      void  *buf_addr;
      unsigned short  *ret_len;
   } LnmItems [] =
   {
      { 255, LNM$_STRING, 0, &ShortLength },
      { 0,0,0,0 }
   };

   int  status;
   char  *cptr;

   /*********/
   /* begin */
   /*********/

   if (Debug) fprintf (stdout, "SysTrnLnm() |%s|\n", LogName);

   LogNameDsc.dsc$a_pointer = LogName;
   LogNameDsc.dsc$w_length = strlen(LogName);
   if (LogValue)
      cptr = LnmItems[0].buf_addr = LogValue;
   else
      cptr = LnmItems[0].buf_addr = StaticLogValue;

   status = sys$trnlnm (0, &LnmFileDevDsc, &LogNameDsc, 0, &LnmItems);
   if (Debug) fprintf (stdout, "sys$trnlnm() %%X%08.08X\n", status);
   if (!(status & 1))
   {
      if (Debug) fprintf (stdout, "|(null)|\n");
      return (NULL);
   }

   cptr[ShortLength] = '\0';
   if (Debug) fprintf (stdout, "|%s|\n", cptr);
   return (cptr);
}

/*****************************************************************************/
/*
Parses the string passed to it as a 'command-line' with parameters and
qualifiers.  Makes the real command-line and the authentication configuration
parameters look and behave in the same fashion.
*/

void GetRunTimeParameters
(
char *clptr,
BOOL FromCli
)
{
   char  ch;
   char  *aptr, *cptr, *sptr, *zptr;

   /*********/
   /* begin */
   /*********/

   if (Debug) fprintf (stdout, "RunTimeParameters() |%s|\n", clptr);

   aptr = NULL;
   ch = *clptr;
   for (;;)
   {
      if (aptr && *aptr == '/') *aptr = '\0';
      if (!ch) break;

      *clptr = ch;
      if (Debug) fprintf (stdout, "clptr |%s|\n", clptr);
      while (*clptr && isspace(*clptr)) *clptr++ = '\0';
      aptr = clptr;
      if (*clptr == '/') clptr++;
      while (*clptr && !isspace (*clptr) && *clptr != '/')
      {
         if (*clptr != '\"')
         {
            clptr++;
            continue;
         }
         cptr = clptr;
         clptr++;
         while (*clptr)
         {
            if (*clptr == '\"')
               if (*(clptr+1) == '\"')
                  clptr++;
               else
                  break;
            *cptr++ = *clptr++;
         }
         *cptr = '\0';
         if (*clptr) clptr++;
      }
      ch = *clptr;
      if (*clptr) *clptr = '\0';
      if (Debug) fprintf (stdout, "aptr |%s|\n", aptr);
      if (!*aptr) continue;

      if (FromCli && strsame (aptr, "/AUTH_PASSWORD=", 4))
      {
         for (cptr = aptr; *cptr && *cptr != '='; cptr++);
         if (!*cptr) continue;
         cptr++;
         strzcpy (CliAuthPassword, cptr, sizeof(CliAuthPassword));
         continue;
      }

      if (strsame (aptr, "/BASE=", 4))
      {
         for (cptr = aptr; *cptr && *cptr != '='; cptr++);
         if (!*cptr) continue;
         cptr++;
         strzcpy (LdapBase, cptr, sizeof(LdapBase));
         continue;
      }

      if (strsame (aptr, "/CERT=", 4))
      {
         for (cptr = aptr; *cptr && *cptr != '='; cptr++);
         if (!*cptr) continue;
         cptr++;
         strzcpy (CertKeyFileName, cptr, sizeof(CertKeyFileName));
         continue;
      }

      if (strsame (aptr, "/DATT=", 4))
      {
         for (cptr = aptr; *cptr && *cptr != '='; cptr++);
         if (!*cptr) continue;
         cptr++;
         strzcpy (UserDisplayAttribute, cptr, sizeof(UserDisplayAttribute));
         continue;
      }

      if (FromCli && strsame (aptr, "/DBUG", -1))
      {
         Debug = TRUE;
         continue;
      }

      if (strsame (aptr, "/FILTER=", 4))
      {
         for (cptr = aptr; *cptr && *cptr != '='; cptr++);
         if (!*cptr) continue;
         cptr++;
         strzcpy (LdapFilter, cptr, sizeof(LdapFilter));
         continue;
      }

      if (strsame (aptr, "/HOST=", 4) ||
          strsame (aptr, "/SERVER=", 4))
      {
         for (cptr = aptr; *cptr && *cptr != '='; cptr++);
         if (!*cptr) continue;
         cptr++;
         strzcpy (LdapHost, cptr, sizeof(LdapHost));
         for (cptr = LdapHost; *cptr && *cptr != ':'; cptr++);
         if (*cptr)
         {
            *cptr++ = '\0';
            if (isdigit(*cptr)) LdapPort = (short)atoi(cptr);
         }
         continue;
      }

      if (strsame (aptr, "/PORT=", 4))
      {
         for (cptr = aptr; *cptr && *cptr != '='; cptr++);
         if (*cptr) cptr++;
         LdapPort = (short)atoi(cptr);
         continue;
      }

      if (FromCli && strsame (aptr, "/REMOTE_USER=", 4))
      {
         for (cptr = aptr; *cptr && *cptr != '='; cptr++);
         if (!*cptr) continue;
         cptr++;
         strzcpy (CliRemoteUser, cptr, sizeof(CliRemoteUser));
         continue;
      }

      if (strsame (aptr, "/RESET", 4))
      {
         LdapPort = LdapSSL = StartTLS = 0;
         LdapProtocolVersion = LDAP_VERSION3;

         CertKeyFileName[0] =
            CliAuthPassword[0] =
            CliRemoteUser[0] =
            LdapBase[0] =
            LdapFilter[0] =
            LdapHost[0] =
            UserDisplayAttribute[0] =
            UserNameDefault[0] =
            UserNameAttribute[0] = '\0';

         strcpy (UserDisplayAttribute, DEFAULT_ATTRIBUTE_DISPLAY);
         strcpy (UserNameAttribute, DEFAULT_ATTRIBUTE_USERNAME);

         continue;
      }

      if (strsame (aptr, "/SSL=", 4))
      {
         LdapSSL = 1;  /* the default; TLSv1 */
         for (cptr = aptr; *cptr && *cptr != '='; cptr++);
         if (!*cptr) continue;
         cptr++;
         LdapSSL = atoi(cptr);
         continue;
      }

      if (strsame (aptr, "/TLS=", 4))
      {
         StartTLS = 1;  /* the default; TLSv1 */
         for (cptr = aptr; *cptr && *cptr != '='; cptr++);
         if (!*cptr) continue;
         cptr++;
         StartTLS = atoi(cptr);
         continue;
      }

      if (strsame (aptr, "/UDEF=", 4))
      {
         for (cptr = aptr; *cptr && *cptr != '='; cptr++);
         if (!*cptr) continue;
         cptr++;
         strzcpy (UserNameDefault, cptr, sizeof(UserNameDefault));
         continue;
      }

      if (strsame (aptr, "/UATT=", 4))
      {
         for (cptr = aptr; *cptr && *cptr != '='; cptr++);
         if (!*cptr) continue;
         cptr++;
         strzcpy (UserNameAttribute, cptr, sizeof(UserNameAttribute));
         continue;
      }

      if (strsame (aptr, "/VERSION=", 4))
      {
         LdapProtocolVersion = LDAP_VERSION3;
         for (cptr = aptr; *cptr && *cptr != '='; cptr++);
         if (!*cptr) continue;
         cptr++;
         LdapProtocolVersion = atoi(cptr);
         continue;
      }

      if (FromCli && strsame (aptr, "/WATCH", -1))
      {
         DebugWatch = TRUE;
         continue;
      }

      if (FromCli)
      {
         if (*aptr == '/')
         {
            fprintf (stdout, "%%%s-E-IVQUAL, unrecognized qualifier\n \\%s\\\n",
                     Utility, aptr+1);
            exit (STS$K_ERROR | STS$M_INHIB_MSG);
         }
         else
         {
            fprintf (stdout, "%%%s-E-MAXPARM, too many parameters\n \\%s\\\n",
                     Utility, aptr);
            exit (STS$K_ERROR | STS$M_INHIB_MSG);
         }
      }
   }
}

/*****************************************************************************/
/*
Get "command-line" parameters, whether from the command-line.
*/

void GetParameters ()

{
   static char  CommandLine [512];
   static unsigned long  Flags = 0;

   int  status;
   unsigned short  Length;
   $DESCRIPTOR (CommandLineDsc, CommandLine);

   /*********/
   /* begin */
   /*********/

   if (Debug) fprintf (stdout, "GetParameters()\n");

   /* get the entire command line following the verb */
   status = lib$get_foreign (&CommandLineDsc, 0, &Length, &Flags);
   if (VMSnok (status)) exit (status);

   CommandLine[Length] = '\0';
   GetRunTimeParameters (CommandLine, TRUE);
}

/****************************************************************************/
/*
Copy a string without overflow (or indication of it :-).
*/ 

int strzcpy
(
char *String,
char *cptr,
int SizeOfString
)
{
   char  *sptr, *zptr;

   /*********/
   /* begin */
   /*********/

   if (SizeOfString) SizeOfString--;
   zptr = (sptr = String) + SizeOfString;
   while (*cptr && sptr < zptr) *sptr++ = *cptr++;
   *sptr = '\0';
   return (sptr - String);
}

/****************************************************************************/
/*
Does a case-insensitive, character-by-character string compare and returns 
TRUE if two strings are the same, or FALSE if not.  If a maximum number of 
characters are specified only those will be compared, if the entire strings 
should be compared then specify the number of characters as 0.
*/ 

BOOL strsame
(
char *sptr1,
char *sptr2,
int  count
)
{
   /*********/
   /* begin */
   /*********/

   while (*sptr1 && *sptr2)
   {
      if (toupper (*sptr1++) != toupper (*sptr2++)) return (FALSE);
      if (count)
         if (!--count) return (TRUE);
   }
   if (*sptr1 || *sptr2)
      return (FALSE);
   else
      return (TRUE);
}

/*****************************************************************************/

