export const getCases = async (req: Request, res: Response): Promise<Response> => {
  try {
    const page = parseInt(req.query.page as string) || 1;
    const limit = parseInt(req.query.limit as string) || 10;
    const skip = (page - 1) * limit;
    const filters = req.query;
    const query = { ...filters };
    delete query.page;
    delete query.limit;
    delete query.sort;

    // Handle role-based access
    if (req.user.role === 'client') {
      query.client = req.user._id;
    } else if (req.user.role === 'lawyer') {
      query.assignedLawyer = req.user._id;
    }

    const cases = await Case.find(query)
      .populate('client', 'firstName lastName email')
      .populate('assignedLawyer', 'firstName lastName email')
      .skip(skip)
      .limit(limit)
      .sort(req.query.sort as string || '-createdAt');

    const total = await Case.countDocuments(query);

    return res.status(200).json({
      success: true,
      count: total,
      data: cases,
      totalPages: Math.ceil(total / limit),
      currentPage: page
    });
