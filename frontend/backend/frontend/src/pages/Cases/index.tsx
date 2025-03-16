  const [cases, setCases] = useState<Case[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [pagination, setPagination] = useState({
    page: 1,
    limit: 10,
    total: 0,
    totalPages: 1
  });
        const params = {
          page: 1,
          limit: 10,
          sort: '-createdAt',
          ...Object.fromEntries(
            new URLSearchParams(window.location.search)
          )
        };
        const data = await getCases(params);
        setCases(data.data);
        setPagination({
          page: data.currentPage,
          limit: pagination.limit,
          total: data.count,
          totalPages: data.totalPages
        });
