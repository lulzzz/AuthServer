using Microsoft.AspNet.Identity;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Net;
using System.Net.Mail;
using System.Threading.Tasks;
using System.Web;

namespace VTS.AuthServer.Web.Services
{
    public class EmailService: IIdentityMessageService
    {
        private const string smtpHost = "smtp.mailgun.org";
        private const string smtpUser = "postmaster@vehicletracking.com";
        private const string smtpPassword = "6e946348079d39069da1b11a11838355";

        public async Task SendAsync(IdentityMessage message)
        {
            await SendMailAsync(message);
        }
 
        private async Task SendMailAsync(IdentityMessage message)
        {
            var myMessage = new System.Net.Mail.MailMessage();
 
            myMessage.To.Add(message.Destination);
            myMessage.From = new System.Net.Mail.MailAddress("membership@vehicletracking.com", "VTS Member Services");
            myMessage.Subject = message.Subject;
            myMessage.Body = message.Body;
            myMessage.IsBodyHtml = true;
 
            // Create a Web transport for sending email.
            var smtpClient = new System.Net.Mail.SmtpClient
            {
                Host = smtpHost,
                Port = 587,
                EnableSsl = true,
                DeliveryMethod = SmtpDeliveryMethod.Network,
                UseDefaultCredentials = false,
                Credentials = new NetworkCredential(smtpUser, smtpPassword)
            };
 
            // Send the email.
            if (smtpClient != null)
            {
                try
                {
                    await smtpClient.SendMailAsync(myMessage);
                }
                catch (Exception)
                {

                }
            }
            else
            {
                await Task.FromResult(0);
            }
        }
    }
}