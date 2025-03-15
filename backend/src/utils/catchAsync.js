/**
 * Wrapper function to catch async errors
 * Eliminates the need for try/catch blocks in controllers
 * 
 * @param {Function} fn - Async function to wrap
 * @returns {Function} Express middleware function that executes the wrapped function
 */
const catchAsync = fn => {
  return (req, res, next) => {
    // Execute the passed function and catch any errors
    Promise.resolve(fn(req, res, next)).catch(next);
  };
};

module.exports = catchAsync;

