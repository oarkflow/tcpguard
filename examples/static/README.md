# TCPGuard Testing Dashboard

A comprehensive web interface for testing and demonstrating TCPGuard's anomaly detection capabilities.

## Features

- **Real-time Testing**: Test all anomaly detection rules interactively
- **Live Metrics**: Monitor system performance and detection statistics
- **Visual Feedback**: Color-coded results and status indicators
- **Comprehensive Coverage**: Test DDoS, MITM, business hours, session hijacking, and more

## Getting Started

1. Start the TCPGuard server:
   ```bash
   cd examples
   go run main.go
   ```

2. Open your browser and navigate to:
   ```
   http://localhost:3000
   ```

## Dashboard Sections

### System Status
- Real-time health monitoring
- Service status indicators
- System uptime tracking

### DDoS Attack Simulation
- Configurable request rates
- Duration control
- Live progress tracking
- Rate limiting demonstration

### MITM Detection Test
- User agent manipulation
- Suspicious pattern testing
- Real-time detection feedback

### Business Hours Test
- Time-based access control
- Timezone support
- Business logic validation

### Protected Routes Test
- Authentication testing
- Authorization header validation
- Access control verification

### Session Hijacking Test
- Multi-session simulation
- User agent tracking
- Concurrent session limits

### Login Testing
- Authentication flow testing
- Success/failure scenarios
- Rate limiting on failed attempts

### Real-time Metrics
- Live system statistics
- Detection counters
- Performance monitoring

### Activity Logs
- Real-time event logging
- Color-coded log levels
- Auto-scrolling log viewer

## Testing Scenarios

### DDoS Attack Simulation
1. Set desired requests per second (1-100)
2. Configure test duration (5-120 seconds)
3. Click "Start DDoS Test"
4. Monitor rate limiting in action
5. View blocked vs successful requests

### MITM Detection
1. Select different user agents from dropdown
2. Click "Test MITM Detection"
3. Observe detection results
4. Try suspicious user agents like "sqlmap" or "python-requests"

### Business Hours
1. Set test time using time picker
2. Select timezone
3. Click "Test Business Hours"
4. See if access would be allowed

### Protected Routes
1. Enter authorization header (or leave empty)
2. Select route to test
3. Click "Test Protected Route"
4. Observe authentication requirements

### Session Security
1. Enter user ID
2. Set user agent
3. Configure concurrent sessions
4. Click "Test Session Security"
5. Monitor hijacking detection

## API Endpoints

The dashboard uses these endpoints:

- `GET /` - Main dashboard
- `GET /health` - System health check
- `GET /api/metrics` - Real-time metrics
- `POST /api/login` - Authentication testing
- `GET /api/status` - General status endpoint
- `GET /api/protected` - Protected resource
- `GET /api/admin` - Admin-only resource
- `GET /api/test/:scenario` - Various test scenarios

## Configuration

The dashboard automatically detects and works with your TCPGuard configuration files in the `configs/` directory.

## Browser Support

- Chrome 70+
- Firefox 65+
- Safari 12+
- Edge 79+

## Troubleshooting

### Dashboard Not Loading
- Ensure the server is running on port 3000
- Check browser console for JavaScript errors
- Verify static files are being served

### Tests Not Working
- Check that configuration files exist
- Verify rule engine is properly initialized
- Check server logs for errors

### Metrics Not Updating
- Ensure metrics collection is enabled
- Check network connectivity
- Verify API endpoints are responding

## Development

To modify the dashboard:

1. Edit `static/index.html` for structure
2. Modify `static/styles.css` for styling
3. Update `static/app.js` for functionality
4. Restart the server to see changes

## Security Note

This testing dashboard is designed for development and testing purposes. In production environments, consider:

- IP restrictions for dashboard access
- Authentication requirements
- Rate limiting on test endpoints
- Logging of test activities
