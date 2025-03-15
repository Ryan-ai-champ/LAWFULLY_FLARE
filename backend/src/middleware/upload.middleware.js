const multer = require('multer');
const { S3Client, PutObjectCommand } = require('@aws-sdk/client-s3');
const multerS3 = require('multer-s3');
const path = require('path');
const crypto = require('crypto');
const ApiError = require('../utils/apiError');
const logger = require('../utils/logger');
const config = require('../config/config');

// Initialize S3 client
const s3 = new S3Client({
  region: config.aws.region,
  credentials: {
    accessKeyId: config.aws.accessKey,
    secretAccessKey: config.aws.secretKey
  }
});

// File type validation
const fileFilter = (req, file, cb) => {
  // Allowed file types
  const allowedFileTypes = {
    'image': ['image/jpeg', 'image/png', 'image/gif', 'image/webp'],
    'document': ['application/pdf', 'application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'],
    'spreadsheet': ['application/vnd.ms-excel', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'],
    'all': ['image/jpeg', 'image/png', 'image/gif', 'image/webp', 'application/pdf', 'application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', 'application/vnd.ms-excel', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet']
  };
  
  // Get file type from request or default to 'all'
  const fileType = req.query.fileType || 'all';
  
  if (!allowedFileTypes[fileType] || !allowedFileTypes[fileType].includes(file.mimetype)) {
    return cb(new ApiError(400, `Invalid file type. Allowed types: ${allowedFileTypes[fileType].join(', ')}`), false);
  }
  
  cb(null, true);
};

// Generate unique filename
const generateFileName = (file) => {
  const fileExt = path.extname(file.originalname);
  const fileName = `${crypto.randomBytes(16).toString('hex')}${fileExt}`;
  return fileName;
};

// Configure multer storage
const storage = multerS3({
  s3: s3,
  bucket: config.aws.bucket,
  contentType: multerS3.AUTO_CONTENT_TYPE,
  key: (req, file, cb) => {
    // Get user ID from authenticated request
    const userId = req.user ? req.user.id : 'anonymous';
    
    // Create path based on file type, user ID, and date
    const date = new Date().toISOString().split('T')[0];
    const fileType = file.mimetype.split('/')[0];
    const folderPath = `uploads/${fileType}/${userId}/${date}`;
    
    // Generate unique filename
    const fileName = generateFileName(file);
    
    // Set S3 key (path + filename)
    const key = `${folderPath}/${fileName}`;
    
    // Store path in request for later use
    req.uploadPath = folderPath;
    
    cb(null, key);
  },
  metadata: (req, file, cb) => {
    cb(null, {
      originalName: file.originalname,
      userId: req.user ? req.user.id : 'anonymous',
      uploadDate: new Date().toISOString()
    });
  }
});

// Create multer middleware instances
const uploadSingle = (fieldName, fileType) => {
  return (req, res, next) => {
    // Set file type in request
    req.query.fileType = fileType || 'all';
    
    // Size limits based on file type
    const limits = {
      fileSize: fileType === 'image' ? config.upload.imageSizeLimit : config.upload.documentSizeLimit
    };
    
    // Create upload middleware
    const upload = multer({
      storage,
      fileFilter,
      limits
    }).single(fieldName);
    
    // Execute upload
    upload(req, res, (err) => {
      if (err) {
        if (err instanceof multer.MulterError) {
          // Multer error handling
          if (err.code === 'LIMIT_FILE_SIZE') {
            return next(new ApiError(400, `File too large. Maximum size: ${limits.fileSize / (1024 * 1024)}MB`));
          }
          return next(new ApiError(400, `Upload error: ${err.message}`));
        } else {
          // Other errors (including custom ApiErrors from fileFilter)
          return next(err);
        }
      }
      
      // If no file was uploaded
      if (!req.file) {
        return next(new ApiError(400, 'No file uploaded'));
      }
      
      // Add file URL to request
      req.fileUrl = req.file.location;
      
      // Log successful upload
      logger.info(`File uploaded successfully: ${req.file.key}`);
      
      next();
    });
  };
};

// Upload multiple files
const uploadMultiple = (fieldName, fileType, maxCount = 5) => {
  return (req, res, next) => {
    // Set file type in request
    req.query.fileType = fileType || 'all';
    
    // Size limits based on file type
    const limits = {
      fileSize: fileType === 'image' ? config.upload.imageSizeLimit : config.upload.documentSizeLimit,
      files: maxCount
    };
    
    // Create upload middleware
    const upload = multer({
      storage,
      fileFilter,
      limits
    }).array(fieldName, maxCount);
    
    // Execute upload
    upload(req, res, (err) => {
      if (err) {
        if (err instanceof multer.MulterError) {
          // Multer error handling
          if (err.code === 'LIMIT_FILE_SIZE') {
            return next(new ApiError(400, `File too large. Maximum size: ${limits.fileSize / (1024 * 1024)}MB`));
          } else if (err.code === 'LIMIT_FILE_COUNT') {
            return next(new ApiError(400, `Too many files. Maximum: ${maxCount}`));
          }
          return next(new ApiError(400, `Upload error: ${err.message}`));
        } else {
          // Other errors
          return next(err);
        }
      }
      
      // If no files were uploaded
      if (!req.files || req.files.length === 0) {
        return next(new ApiError(400, 'No files uploaded'));
      }
      
      // Add file URLs to request
      req.fileUrls = req.files.map(file => file.location);
      
      // Log successful upload
      logger.info(`${req.files.length} files uploaded successfully`);
      
      next();
    });
  };
};

// Delete file from S3
const deleteFile = async (key) => {
  try {
    const params = {
      Bucket: config.aws.bucket,
      Key: key
    };
    
    await s3.send(new DeleteObjectCommand(params));
    logger.info(`File deleted successfully: ${key}`);
    return true;
  } catch (error) {
    logger.error(`Error deleting file from S3: ${error.message}`);
    throw new ApiError(500, 'Failed to delete file');
  }
};

module.exports = {
  uploadSingle,
  uploadMultiple,
  deleteFile
};

