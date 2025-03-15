import React from "react";
import { ThemeProvider, createTheme } from "@mui/material/styles";
import { Container, AppBar, Toolbar, Typography, Box } from "@mui/material";
import CssBaseline from "@mui/material/CssBaseline";
import ConnectionTest from "./components/ConnectionTest";

const theme = createTheme({
  palette: {
    primary: {
      main: "#1976d2",
    },
    secondary: {
      main: "#dc004e",
    },
  },
});

function App() {
  return (
    <ThemeProvider theme={theme}>
      <CssBaseline />
      <AppBar position="static">
        <Toolbar>
          <Typography variant="h6">
            Immigration Case Management System
          </Typography>
        </Toolbar>
      </AppBar>
      <Container maxWidth="lg">
        <Box sx={{ mt: 4 }}>
          <Typography variant="h4" gutterBottom>
            System Status
          </Typography>
          <ConnectionTest />
        </Box>
      </Container>
    </ThemeProvider>
  );
}

export default App;
