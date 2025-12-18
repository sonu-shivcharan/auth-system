function asyncHandler(requestFn) {
  return (req, res, next) => {
    Promise.resolve(requestFn(req, res)).catch((err) => next(err));
  };
}

export { asyncHandler };
