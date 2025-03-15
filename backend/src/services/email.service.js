const nodemailer = require('nodemailer');
const config = require('../config');
const logger = require('../utils/logger');

class EmailService {
  constructor() {
    this.transporter = nodemailer.createTransport({
      host: config.email.host,
      port: config.email.port,
      secure: config.email.secure,
      auth: {
        user: config.email.user,
        pass: config.email.password,
      },
    });
  }

  /**
   * Send an email
   * @param {Object} options - Email options
   * @param {string} options.to - Recipient email
   * @param {string} options.subject - Email subject
   * @param {string} options.text - Plain text content
   * @param {string} options.html - HTML content
   * @returns {Promise<Object>} - Email sending result
   */
  async sendEmail(options) {
    try {
      const { to, subject, text, html } = options;
      
      const mailOptions = {
        from: config.email.from,
        to,
        subject,
        text,
        html,
      };

      const info = await this.transporter.sendMail(mailOptions);
      logger.info(`Email sent to ${to}: ${info.messageId}`);
      return info;
    } catch (error) {
      logger.error(`Error sending email: ${error.message}`);
      throw new Error(`Failed to send email: ${error.message}`);
    }
  }

  /**
   * Send a verification email
   * @param {string} to - Recipient email
   * @param {string} token - Verification token
   * @returns {Promise<Object>} - Email sending result
   */
  async sendVerificationEmail(to, token) {
    try {
      const verificationUrl = `${config.clientUrl}/verify-email?token=${token}`;
      
      const subject = 'Email Verification';
      const text = `Please verify your email by clicking on the following link: ${verificationUrl}`;
      const html = `
        <h1>Email Verification</h1>
        <p>Please verify your email by clicking on the link below:</p>
        <a href="${verificationUrl}">Verify Email</a>
      `;

      return await this.sendEmail({ to, subject, text, html });
    } catch (error) {
      logger.error(`Error sending verification email: ${error.message}`);
      throw new Error(`Failed to send verification email: ${error.message}`);
    }
  }

  /**
   * Send a password reset email
   * @param {string} to - Recipient email
   * @param {string} token - Password reset token
   * @returns {Promise<Object>} - Email sending result
   */
  async sendPasswordResetEmail(to, token) {
    try {
      const resetUrl = `${config.clientUrl}/reset-password?token=${token}`;
      
      const subject = 'Password Reset';
      const text = `You requested a password reset. Please click on the following link to reset your password: ${resetUrl}`;
      const html = `
        <h1>Password Reset</h1>
        <p>You requested a password reset. Please click on the link below to reset your password:</p>
        <a href="${resetUrl}">Reset Password</a>
      `;

      return await this.sendEmail({ to, subject, text, html });
    } catch (error) {
      logger.error(`Error sending password reset email: ${error.message}`);
      throw new Error(`Failed to send password reset email: ${error.message}`);
    }
  }

  /**
   * Send a case status update email
   * @param {string} to - Recipient email
   * @param {Object} caseData - Case data
   * @returns {Promise<Object>} - Email sending result 
   */
  async sendCaseStatusUpdateEmail(to, caseData) {
    try {
      const { caseNumber, status, message } = caseData;
      
      const subject = `Case Status Update: ${caseNumber}`;
      const text = `Your case ${caseNumber} has been updated to: ${status}.\n\n${message || ''}`;
      const html = `
        <h1>Case Status Update</h1>
        <p>Your case <strong>${caseNumber}</strong> has been updated.</p>
        <p>New Status: <strong>${status}</strong></p>
        ${message ? `<p>${message}</p>` : ''}
      `;

      return await this.sendEmail({ to, subject, text, html });
    } catch (error) {
      logger.error(`Error sending case status update email: ${error.message}`);
      throw new Error(`Failed to send case status update email: ${error.message}`);
    }
  }
}

// Singleton instance
const emailService = new EmailService();

module.exports = emailService;

