// Censys Data Summarizer - File Upload Version
  
  // DOM elements
  const dataInput = document.getElementById('data-input');
  const fileInput = document.getElementById('file-input');
  const clearBtn = document.getElementById('clear-btn');
  const summarizeBtn = document.getElementById('summarize-btn');
  const loading = document.getElementById('loading');
  const results = document.getElementById('results');
  const error = document.getElementById('error');
  const metricsContainer = document.getElementById('metrics');
  const summaryContent = document.getElementById('summary-content');
  const errorMessage = document.getElementById('error-message');
  
  // Event listeners
  fileInput.addEventListener('change', handleFileUpload);
  clearBtn.addEventListener('click', clearInput);
  summarizeBtn.addEventListener('click', summarizeData);
  
  function handleFileUpload(event) {
      const file = event.target.files[0];
      if (!file) return;
      
      if (file.type !== 'application/json') {
          showError('Please select a valid JSON file.');
          return;
      }
      
      const reader = new FileReader();
      reader.onload = function(e) {
          try {
              const jsonData = JSON.parse(e.target.result);
              dataInput.value = JSON.stringify(jsonData, null, 2);
              hideError();
          } catch (error) {
              showError('Invalid JSON file. Please check the file format.');
          }
      };
      reader.readAsText(file);
  }
  
  function clearInput() {
      dataInput.value = '';
      fileInput.value = '';
      hideError();
      hideResults();
  }
  
  function hideError() {
      error.classList.add('hidden');
  }
  
  function hideResults() {
      results.classList.add('hidden');
  }
  
  function showError(message) {
      errorMessage.textContent = message;
      error.classList.remove('hidden');
      results.classList.add('hidden');
      loading.classList.add('hidden');
  }
  
  async function summarizeData() {
      const data = dataInput.value.trim();
      
      if (!data) {
          showError('Please enter or load some data to summarize.');
          return;
      }
      
      // Validate JSON
      try {
          JSON.parse(data);
      } catch (e) {
          showError('Invalid JSON format. Please check your input.');
          return;
      }
      
      // Show loading state
      loading.classList.remove('hidden');
      results.classList.add('hidden');
      hideError();
      
      try {
          const response = await fetch('/summarize', {
              method: 'POST',
              headers: {
                  'Content-Type': 'application/json',
              },
              body: JSON.stringify(JSON.parse(data))
          });
          
          const result = await response.json();
          
          if (!response.ok) {
              throw new Error(result.error || 'Unknown error occurred');
          }
          
          // Display results
          displayMetrics(result.metrics);
          displaySummary(result.summary);
          
          loading.classList.add('hidden');
          results.classList.remove('hidden');
          
      } catch (err) {
          showError(err.message);
      }
  }
  
  function displayMetrics(metrics) {
      metricsContainer.innerHTML = '';
      
      const metricCards = [
          { label: 'Total Hosts', value: metrics.total_hosts },
          { label: 'Critical Risk', value: metrics.critical_risk },
          { label: 'High Risk', value: metrics.high_risk },
          { label: 'Services', value: metrics.services_count },
          { label: 'Unique Vulnerabilities', value: metrics.unique_vulnerabilities.length },
          { label: 'Countries', value: metrics.countries.join(', ') }
      ];
      
      metricCards.forEach(metric => {
          const card = document.createElement('div');
          card.className = 'metric-card';
          card.innerHTML = `
              <div class="metric-value">${metric.value}</div>
              <div class="metric-label">${metric.label}</div>
          `;
          metricsContainer.appendChild(card);
      });
  }
  
  function displaySummary(summary) {
      try {
          if (typeof marked !== 'undefined' && marked.parse) {
              summaryContent.innerHTML = marked.parse(summary);
          } else {
              summaryContent.textContent = summary;
          }
      } catch (e) {
          summaryContent.textContent = summary;
      }
  }
