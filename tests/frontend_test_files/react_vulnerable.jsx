import React from 'react';

function VulnerableComponent({ userInput }) {
    // Vulnerability 1: Direct XSS via dangerouslySetInnerHTML
    return (
        <div>
            <h1>Welcome</h1>
            <div dangerouslySetInnerHTML={{ __html: userInput }} />

            {/* Vulnerability 2: Prop Drilling Risk (detected by prop name heuristic) */}
            <ChildComponent htmlContent={userInput} />
        </div>
    );
}

function ChildComponent({ htmlContent }) {
    return <div>{htmlContent}</div>;
}

export default VulnerableComponent;
