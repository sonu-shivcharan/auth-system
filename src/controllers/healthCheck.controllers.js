import { ApiResponse } from "../utils/api-response.js";
import { asyncHandler } from "../utils/async-handler.js";
import logger from "../utils/logger.js";

// const healthCheck = (req, res) => {
//   try {
//     res.status(200).json(new ApiResponse(200, {}, "Server is up and running"));
//   } catch (error) {}
// };

const healthCheck = asyncHandler(async (req, res) => {
  logger.info("Health check");
  res.status(200).json(new ApiResponse(200, {}, "message"));
});

export { healthCheck };
